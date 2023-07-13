package poa

import (
	"crypto/rsa"
	"encoding/base64"
	"strings"
)

var encoding = base64.RawURLEncoding

type JWT struct {
	Header    []byte
	Body      []byte
	Signature []byte
	raw       string
}

func decode(s string) []byte {
	decoded := make([]byte, encoding.DecodedLen(len(s)))
	encoding.Decode(decoded, []byte(s))
	return decoded
}

func ParseJWT(jwt string) JWT {
	parts := strings.SplitN(jwt, ".", 3)
	return JWT{
		Header:    decode(parts[0]),
		Body:      decode(parts[1]),
		Signature: decode(parts[2]),
		raw:       jwt,
	}
}

func (j *JWT) SignedPart() []byte {
	return []byte(j.raw[:strings.LastIndexByte(j.raw, '.')])
}

func (j *JWT) Verify(pub *rsa.PublicKey) bool {
	return VerifyPKCS1v15SHA256(pub, j.SignedPart(), j.Signature)
}

func (j *JWT) StripSignature() JWTNoSignature {
	return JWTNoSignature{j.Header, j.Body, string(j.SignedPart())}
}

func (j *JWT) GQProve(pub *rsa.PublicKey) GQProof {
	N, E, m := PreparePKCS1v15SHA256ForRSACheck(pub, j.SignedPart())
	gqPub := GQPublic{N, E, m}
	gqPriv := GQPrivate{ParseSig(j.Signature, N)}
	return GQProve(gqPub, gqPriv)
}

type JWTNoSignature struct {
	Header []byte
	Body   []byte
	raw    string
}

func ParseJWTNoSignature(jwt string) JWTNoSignature {
	parts := strings.SplitN(jwt, ".", 2)
	return JWTNoSignature{
		Header: decode(parts[0]),
		Body:   decode(parts[1]),
		raw:    jwt,
	}
}

func (j *JWTNoSignature) GQVerify(pub *rsa.PublicKey, proof GQProof) bool {
	N, E, m := PreparePKCS1v15SHA256ForRSACheck(pub, []byte(j.raw))
	gqPub := GQPublic{N, E, m}
	return GQVerify(gqPub, proof)
}
