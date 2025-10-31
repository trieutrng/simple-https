package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
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

func GetSharedSecretX25519(privateKey, publicKey []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, err
	}
	return sharedSecret, nil
}

func HashSha256(data []byte) []byte {
	sha_256 := sha256.New()
	sha_256.Write(data)
	return sha_256.Sum(nil)
}

/*https://datatracker.ietf.org/doc/html/rfc8446#autoid-68

HKDF-Expand-Label(Secret, Label, Context, Length) =

	     HKDF-Expand(Secret, HkdfLabel, Length)

	Where HkdfLabel is specified as:

	struct {
	    uint16 length = Length;
	    opaque label<7..255> = "tls13 " + Label;
	    opaque context<0..255> = Context;
	} HkdfLabel;

	Derive-Secret(Secret, Label, Messages) =
	     HKDF-Expand-Label(Secret, Label,
	                       Transcript-Hash(Messages), Hash.length)
*/

func HKDFExtract(hashFunc func() hash.Hash, secret, salt []byte) []byte {
	return hkdf.Extract(hashFunc, secret, salt)
}

func HKDFExpandLabel(hashFunc func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	// build HkdfLabel structure
	hkdfLabel := new(bytes.Buffer)

	// uint16 length
	binary.Write(hkdfLabel, binary.BigEndian, uint16(length))

	// opaque label = "tls13 " + label
	fullLabel := append([]byte("tls13 "), label...)
	hkdfLabel.WriteByte(byte(len(fullLabel)))
	hkdfLabel.Write(fullLabel)

	// opaque context
	hkdfLabel.WriteByte(byte(len(context)))
	hkdfLabel.Write(context)

	// HKDF-Expand
	okm := make([]byte, length)
	h := hkdf.Expand(hashFunc, secret, hkdfLabel.Bytes())
	if _, err := io.ReadFull(h, okm); err != nil {
		panic(err)
	}
	return okm
}

func AESGCMDecrypt(key, iv, wrapper []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	additional := wrapper[:5]
	ciphertext := wrapper[5:]
	plaintext, err := aesgcm.Open(nil, iv, ciphertext, additional)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func AESGCMEncrypt(key, iv, plaintext, additional []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	ciphertext := aesgcm.Seal(nil, iv, plaintext, additional)
	return append(additional, ciphertext...)
}
