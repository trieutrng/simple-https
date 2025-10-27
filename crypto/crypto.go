package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

func Random(len int) []byte {
	buf := make([]byte, len)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return buf
}

type KeyPair struct {
	Private []byte
	Public  []byte
}

func GetX25519KeyPair() (*KeyPair, error) {
	privateKey := Random(32)
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return &KeyPair{privateKey, publicKey}, nil
}
