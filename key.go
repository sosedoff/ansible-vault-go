package vault

import (
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

type key struct {
	cipherKey []byte
	hmacKey   []byte
	iv        []byte
}

func generateKey(password string, salt []byte) *key {
	k := pbkdf2.Key([]byte(password), salt, operations, 2*keyLength+ivLength, sha256.New)

	return &key{
		cipherKey: k[:keyLength],
		hmacKey:   k[keyLength:(keyLength * 2)],
		iv:        k[(keyLength * 2) : (keyLength*2)+ivLength],
	}
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
