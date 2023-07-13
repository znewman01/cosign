package poa

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// Check A^v = X mod N.
func CheckRSA(n *big.Int, v int, X, A *big.Int) bool {
	return new(big.Int).Exp(A, big.NewInt(int64(v)), n).Cmp(X) == 0
}

func IntToBytes(i int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(i))
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

var prefix = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

func ParseSig(sigBytes []byte, N *big.Int) *big.Int {
	return new(big.Int).SetBytes(sigBytes)
}

func formatMsg(k int, msg []byte, N *big.Int) *big.Int {
	hasher := sha256.New()
	tLen := len(prefix) + hasher.Size()
	// EM = 0x00 || 0x01 || PS || 0x00 || T
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k-hasher.Size()], prefix)
	hasher.Write([]byte(msg))
	copy(em[k-hasher.Size():k], hasher.Sum(nil))
	return new(big.Int).SetBytes(em)
}

func VerifyPKCS1v15SHA256(pub *rsa.PublicKey, msg, sigBytes []byte) bool {
	sig := ParseSig(sigBytes, pub.N)
	m := formatMsg(pub.Size(), msg, pub.N)
	return CheckRSA(pub.N, pub.E, m, sig)
}

func PreparePKCS1v15SHA256ForRSACheck(pub *rsa.PublicKey, msg []byte) (*big.Int, int, *big.Int) {
	m := formatMsg(pub.Size(), msg, pub.N)
	return pub.N, pub.E, m
}
