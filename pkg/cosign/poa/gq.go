package poa

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// Public knowledge:
// - RSA modulus n
// - public RSA exponent v
// - preimage X
//
// Secret knowledge for prover: 𝐴
// A, such that A^v = X mod N
//
//
// r <-$ Z_N^*
// T <- r^v mod n
//                   T   ->
//                                 d <-$ {0, .. v-1}
//                   d   <-
// t <- A^d r mod n
//                   t   ->
//                                 t^v =? X^d T mod n

type FiatShamirHashable interface {
	FSHash() *io.Reader
}

type GQPublic struct {
	N *big.Int // modulus
	V int      // exponent
	X *big.Int // message
}

type GQPrivate struct {
	A *big.Int // signature
}

func checkInput(pub GQPublic, priv GQPrivate) {
	if !CheckRSA(pub.N, pub.V, pub.X, priv.A) {
		panic("uh oh")
	}
}

type aux1 struct {
	r *big.Int
}

type message1 struct {
	T *big.Int
}

func round1prover(rng io.Reader, pub GQPublic, priv GQPrivate) (aux1, message1) {
	// r <-$ Z_N^*
	var r *big.Int
	for {
		// Sample from Z_N^*
		r, _ = rand.Int(rng, pub.N)
		if new(big.Int).GCD(nil, nil, r, pub.N).Cmp(big.NewInt(1)) == 0 {
			break
		}
	}
	// T <- r^v mod n
	T := new(big.Int).Exp(r, big.NewInt(int64(pub.V)), pub.N)
	return aux1{r}, message1{T}
}

type round1info struct {
	Pub  GQPublic
	Msg1 message1
}

func (r *round1info) FSHash() io.Reader {
	rng := sha3.NewShake256()
	rng.Write([]byte(fmt.Sprintf("gq1:%v:%v:%v:%v", r.Pub.N, r.Pub.V, r.Pub.X, r.Msg1.T)))
	return rng
}

func round1verifier(rng io.Reader, info round1info) *big.Int {
	// d <-$ {0, .. v-1}
	d, _ := rand.Int(rng, big.NewInt(int64(info.Pub.V)))
	return d
}

type message2 struct {
	T *big.Int
}

func round2prover(pub GQPublic, priv GQPrivate, aux aux1, d *big.Int) message2 {
	// t <- A^d r mod n
	t := new(big.Int).Exp(priv.A, d, pub.N)
	t.Mul(t, aux.r)
	t.Mod(t, pub.N)
	return message2{t}
}

type round2info struct {
	Round1 round1info
	D      *big.Int
	Msg2   message2
}

func (r *round2info) FSHash() io.Reader {
	xof := sha3.NewShake256()
	xof.Write([]byte(fmt.Sprintf("gq2:%v:%v", r.Round1.FSHash(), r.Msg2.T)))
	return xof
}

func round2verifier(info round2info) bool {
	// t^v =? X^d T mod n
	t := info.Msg2.T
	pub := info.Round1.Pub
	T := info.Round1.Msg1.T
	d := info.D
	lhs := new(big.Int).Exp(t, big.NewInt(int64(pub.V)), pub.N)
	rhs := new(big.Int).Exp(pub.X, d, pub.N)
	rhs.Mul(rhs, T)
	rhs.Mod(rhs, pub.N)
	return (lhs.Cmp(rhs) == 0)
}

type GQProof struct {
	Data round2info
}

func GQProve(pub GQPublic, priv GQPrivate) GQProof {
	aux1, msg1 := round1prover(rand.Reader, pub, priv)
	round1 := round1info{pub, msg1}
	d := round1verifier(round1.FSHash(), round1)

	msg2 := round2prover(pub, priv, aux1, d)
	return GQProof{round2info{round1, d, msg2}}
}

func GQVerify(pub GQPublic, proof GQProof) bool {
	// Correct input.
	if !(proof.Data.Round1.Pub.N.Cmp(pub.N) == 0 &&
		proof.Data.Round1.Pub.V == pub.V &&
		proof.Data.Round1.Pub.X.Cmp(pub.X) == 0) {
		return false
	}

	// Take round1 from prover.

	// Correct first response from verifier.
	d := round1verifier(proof.Data.Round1.FSHash(), proof.Data.Round1)
	if !(d.Cmp(proof.Data.D) == 0) {
		return false
	}

	return round2verifier(proof.Data)
}
