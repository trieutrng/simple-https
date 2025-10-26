package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

func Random(bytes int) []byte {
	buf := make([]byte, bytes)
	rand.Read(buf)
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
		return nil, err
	}
	return &KeyPair{privateKey, publicKey}, nil
}
