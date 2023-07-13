package poa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// Example from https://jwt.io/
const ExampleJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"
const PubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`

func parseKey(t *testing.T, keyPem string) *rsa.PublicKey {
	skDer, _ := pem.Decode([]byte(keyPem))
	key, err := x509.ParsePKIXPublicKey(skDer.Bytes)
	if err != nil {
		t.Fatal("Couldn't parse public key.")
	}
	return key.(*rsa.PublicKey)
}

func TestRSAValidation(t *testing.T) {
	rsaKey := parseKey(t, PubKey)
	jwt := ParseJWT(ExampleJWT)
	if !jwt.Verify(rsaKey) {
		t.Fatal("RSA validation failed.")
	}
}

func TestOIDCGQ(t *testing.T) {
	rsaKey := parseKey(t, PubKey)
	jwt := ParseJWT(ExampleJWT)
	if !jwt.Verify(rsaKey) {
		t.Fatal("sig no validate")
	}
	proof := jwt.GQProve(rsaKey)
	jwtNoSig := jwt.StripSignature()
	if !jwtNoSig.GQVerify(rsaKey, proof) {
		t.Error("gq proof no validate")
	}
}
