//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"bytes"
	"context"
	"crypto"
	_ "crypto/sha256" // for `crypto.SHA256`
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/pkg/errors"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	sigs "github.com/sigstore/cosign/pkg/signature"

	ctypes "github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

func isb64(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

// nolint
func VerifyBlobCmd(ctx context.Context, ko options.KeyOpts, certRef, certEmail,
	certOidcIssuer, certChain, sigRef, blobRef string, enforceSCT bool) error {
	log.Println("start")
	var verifier signature.Verifier
	var cert *x509.Certificate

	if !options.OneOf(ko.KeyRef, ko.Sk, certRef) && !options.EnableExperimental() && ko.BundlePath == "" {
		return &options.PubKeyParseError{}
	}

	sig, b64sig, err := signatures(sigRef, ko.BundlePath)
	if err != nil {
		return err
	}

	blobBytes, err := payloadBytes(blobRef)
	if err != nil {
		return err
	}

	// Keys are optional!
	switch {
	case ko.KeyRef != "":
		verifier, err = sigs.PublicKeyFromKeyRef(ctx, ko.KeyRef)
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
		pkcs11Key, ok := verifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	case ko.Sk:
		sk, err := pivkey.GetKeyWithSlot(ko.Slot)
		if err != nil {
			return errors.Wrap(err, "opening piv token")
		}
		defer sk.Close()
		verifier, err = sk.Verifier()
		if err != nil {
			return errors.Wrap(err, "loading public key from token")
		}
	case certRef != "":
		cert, err = loadCertFromFileOrURL(certRef)
		if err != nil {
			return err
		}
		if certChain == "" {
			verifier, err = signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
			if err != nil {
				return err
			}
		} else {
			// Verify certificate with chain
			chain, err := loadCertChainFromFileOrURL(certChain)
			if err != nil {
				return err
			}
			co := &cosign.CheckOpts{
				CertEmail:      certEmail,
				CertOidcIssuer: certOidcIssuer,
				EnforceSCT:     enforceSCT,
			}
			verifier, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, co)
			if err != nil {
				return err
			}
		}
	case ko.BundlePath != "":
		b, err := cosign.FetchLocalSignedPayloadFromPath(ko.BundlePath)
		if err != nil {
			return err
		}
		if b.Cert == "" {
			return fmt.Errorf("bundle does not contain cert for verification, please provide public key")
		}
		// cert can either be a cert or public key
		certBytes := []byte(b.Cert)
		if isb64(certBytes) {
			certBytes, _ = base64.StdEncoding.DecodeString(b.Cert)
		}
		cert, err = loadCertFromPEM(certBytes)
		if err != nil {
			// check if cert is actually a public key
			verifier, err = sigs.LoadPublicKeyRaw(certBytes, crypto.SHA256)
		} else {
			verifier, err = signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
		}
		if err != nil {
			return err
		}
	case options.EnableExperimental():
		rClient, err := rekor.NewClient(ko.RekorURL)
		if err != nil {
			return err
		}

		log.Println("rekor-online-search:start")
		uuids, err := cosign.FindTLogEntriesByPayload(ctx, rClient, blobBytes)
		log.Println("rekor-online-search:stop")
		if err != nil {
			return err
		}

		if len(uuids) == 0 {
			return errors.New("could not find a tlog entry for provided blob")
		}
		return verifySigByUUID(ctx, ko, rClient, certEmail, certOidcIssuer, sig, b64sig, uuids, blobBytes, enforceSCT)
	}

	// Use the DSSE verifier if the payload is a DSSE with the In-Toto format.
	if isIntotoDSSE(blobBytes) {
		verifier = dsse.WrapVerifier(verifier)
	}

	// verify the signature
	if err := verifier.VerifySignature(bytes.NewReader([]byte(sig)), bytes.NewReader(blobBytes)); err != nil {
		return err
	}

	// verify the rekor entry
	if err := verifyRekorEntry(ctx, ko, nil, verifier, cert, b64sig, blobBytes); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Verified OK")
	log.Println("stop")
	return nil
}

func verifySigByUUID(ctx context.Context, ko options.KeyOpts, rClient *client.Rekor, certEmail, certOidcIssuer, sig, b64sig string,
	uuids []string, blobBytes []byte, enforceSCT bool) error {
	var validSigExists bool
	for _, u := range uuids {
		log.Println("rekor-get:start")
		tlogEntry, err := cosign.GetTlogEntry(ctx, rClient, u)
		log.Println("rekor-get:stop")
		if err != nil {
			continue
		}

		certs, err := extractCerts(tlogEntry)
		if err != nil {
			continue
		}

		log.Println("get-certs:start")
		co := &cosign.CheckOpts{
			RootCerts:         fulcio.GetRoots(),
			IntermediateCerts: fulcio.GetIntermediates(),
			CertEmail:         certEmail,
			CertOidcIssuer:    certOidcIssuer,
			EnforceSCT:        enforceSCT,
		}
		log.Println("get-certs:stop")
		cert := certs[0]
		verifier, err := cosign.ValidateAndUnpackCert(cert, co)
		if err != nil {
			continue
		}
		// Use the DSSE verifier if the payload is a DSSE with the In-Toto format.
		if isIntotoDSSE(blobBytes) {
			verifier = dsse.WrapVerifier(verifier)
		}
		// verify the signature
		if err := verifier.VerifySignature(bytes.NewReader([]byte(sig)), bytes.NewReader(blobBytes)); err != nil {
			continue
		}

		// verify the rekor entry
		if err := verifyRekorEntry(ctx, ko, tlogEntry, verifier, cert, b64sig, blobBytes); err != nil {
			continue
		}
		validSigExists = true
	}
	if !validSigExists {
		fmt.Fprintln(os.Stderr, `WARNING: No valid entries were found in rekor to verify this blob.

Transparency log support for blobs is experimental, and occasionally an entry isn't found even if one exists.

We recommend requesting the certificate/signature from the original signer of this blob and manually verifying with cosign verify-blob --cert [cert] --signature [signature].`)
		return fmt.Errorf("could not find a valid tlog entry for provided blob, found %d invalid entries", len(uuids))
	}
	fmt.Fprintln(os.Stderr, "Verified OK")
	return nil
}

// signatures returns the raw signature and the base64 encoded signature
func signatures(sigRef string, bundlePath string) (string, string, error) {
	var targetSig []byte
	var err error
	switch {
	case sigRef != "":
		targetSig, err = blob.LoadFileOrURL(sigRef)
		if err != nil {
			if !os.IsNotExist(err) {
				// ignore if file does not exist, it can be a base64 encoded string as well
				return "", "", err
			}
			targetSig = []byte(sigRef)
		}
	case bundlePath != "":
		b, err := cosign.FetchLocalSignedPayloadFromPath(bundlePath)
		if err != nil {
			return "", "", err
		}
		targetSig = []byte(b.Base64Signature)
	default:
		return "", "", fmt.Errorf("missing flag '--signature'")
	}

	var sig, b64sig string
	if isb64(targetSig) {
		b64sig = string(targetSig)
		sigBytes, _ := base64.StdEncoding.DecodeString(b64sig)
		sig = string(sigBytes)
	} else {
		sig = string(targetSig)
		b64sig = base64.StdEncoding.EncodeToString(targetSig)
	}
	return sig, b64sig, nil
}

func payloadBytes(blobRef string) ([]byte, error) {
	var blobBytes []byte
	var err error
	if blobRef == "-" {
		blobBytes, err = io.ReadAll(os.Stdin)
	} else {
		blobBytes, err = blob.LoadFileOrURL(blobRef)
	}
	if err != nil {
		return nil, err
	}
	return blobBytes, nil
}

func verifyRekorEntry(ctx context.Context, ko options.KeyOpts, e *models.LogEntryAnon, pubKey signature.Verifier, cert *x509.Certificate, b64sig string, blobBytes []byte) error {
	// If we have a bundle with a rekor entry, let's first try to verify offline
	if ko.BundlePath != "" {
		log.Println("rekor-verify-offline:start")
		if err := verifyRekorBundle(ctx, ko.BundlePath, cert); err == nil {
			fmt.Fprintf(os.Stderr, "tlog entry verified offline\n")
			log.Println("rekor-verify-offline:end")
			return nil
		}
	}
	if !options.EnableExperimental() {
		return nil
	}

	log.Println("rekor-verify-online:start")
	rekorClient, err := rekor.NewClient(ko.RekorURL)
	if err != nil {
		return err
	}
	// Only fetch from rekor tlog if we don't already have the entry.
	if e == nil {
		var pubBytes []byte
		if pubKey != nil {
			pubBytes, err = sigs.PublicKeyPem(pubKey, signatureoptions.WithContext(ctx))
			if err != nil {
				return err
			}
		}
		if cert != nil {
			pubBytes, err = cryptoutils.MarshalCertificateToPEM(cert)
			if err != nil {
				return err
			}
		}
		e, err = cosign.FindTlogEntry(ctx, rekorClient, b64sig, blobBytes, pubBytes)
		if err != nil {
			return err
		}
	}

	if err := cosign.VerifyTLogEntry(ctx, rekorClient, e); err != nil {
		return nil
	}
	log.Println("rekor-verify-online:end")

	uuid, err := cosign.ComputeLeafHash(e)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "tlog entry verified with uuid: %s index: %d\n", hex.EncodeToString(uuid), *e.Verification.InclusionProof.LogIndex)
	if cert == nil {
		return nil
	}
	// if we have a cert, we should check expiry
	return cosign.CheckExpiry(cert, time.Unix(*e.IntegratedTime, 0))
}

func verifyRekorBundle(ctx context.Context, bundlePath string, cert *x509.Certificate) error {
	b, err := cosign.FetchLocalSignedPayloadFromPath(bundlePath)
	if err != nil {
		return err
	}
	if b.Bundle == nil {
		return fmt.Errorf("rekor entry is not available")
	}
	log.Println("tuf:start")
	publicKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		return errors.Wrap(err, "retrieving rekor public key")
	}
	log.Println("tuf:end")

	pubKey, ok := publicKeys[b.Bundle.Payload.LogID]
	if !ok {
		return errors.New("rekor log public key not found for payload")
	}
	err = cosign.VerifySET(b.Bundle.Payload, b.Bundle.SignedEntryTimestamp, pubKey.PubKey)
	if err != nil {
		return err
	}
	if pubKey.Status != tuf.Active {
		fmt.Fprintf(os.Stderr, "**Info** Successfully verified Rekor entry using an expired verification key\n")
	}

	if cert == nil {
		return nil
	}
	it := time.Unix(b.Bundle.Payload.IntegratedTime, 0)
	return cosign.CheckExpiry(cert, it)
}

func extractCerts(e *models.LogEntryAnon) ([]*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.NewEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *rekord.V001Entry:
		publicKeyB64, err = e.RekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	case *hashedrekord.V001Entry:
		publicKeyB64, err = e.HashedRekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unexpected tlog entry type")
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem tlog")
	}

	return certs, err
}

// isIntotoDSSE checks whether a payload is a Dead Simple Signing Envelope with the In-Toto format.
func isIntotoDSSE(blobBytes []byte) bool {
	DSSEenvelope := ssldsse.Envelope{}
	if err := json.Unmarshal(blobBytes, &DSSEenvelope); err != nil {
		return false
	}
	if DSSEenvelope.PayloadType != ctypes.IntotoPayloadType {
		return false
	}

	return true
}
