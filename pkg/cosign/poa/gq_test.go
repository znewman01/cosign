package poa

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"
)

func Setup() (GQPublic, GQPrivate) {
	n := big.NewInt(17 * 7)
	v := 3
	A := big.NewInt(8)
	X := new(big.Int).Exp(A, big.NewInt(int64(v)), n)
	if !CheckRSA(n, v, X, A) {
		panic("bad rsa")
	}
	pub := GQPublic{n, v, X}
	priv := GQPrivate{A}
	return pub, priv
}

func TestGQInteractive(t *testing.T) {
	rng := rand.Reader

	pub, priv := Setup()
	checkInput(pub, priv)

	// Round 1.
	aux1, msg1 := round1prover(rng, pub, priv)
	round1 := round1info{pub, msg1}
	d := round1verifier(rng, round1)

	// Round 2
	msg2 := round2prover(pub, priv, aux1, d)
	if !round2verifier(round2info{round1, d, msg2}) {
		t.Error("uh oh wuh oh")
	}
}

func TestGQNonInteractive(t *testing.T) {
	pub, priv := Setup()
	checkInput(pub, priv)

	proof := GQProve(pub, priv)

	proofJson, _ := json.Marshal(proof)
	proofAfterRoundTrip := GQProof{}
	_ = json.Unmarshal(proofJson, &proofAfterRoundTrip)

	if !GQVerify(pub, proofAfterRoundTrip) {
		t.Error("GQ verification failed.")
	}
}
