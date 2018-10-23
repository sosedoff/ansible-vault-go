package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io/ioutil"
	"strings"
)

const (
	keyLength  = 32
	saltLength = 32
	ivLength   = 16
	operations = 10000
)

// Encrypt encrypts the input string with the vault password
func Encrypt(input string, password string) (string, error) {
	salt, err := generateRandomBytes(saltLength)
	if err != nil {
		return "", err
	}
	key := generateKey(password, salt)

	// Encrypt the secret content
	data, err := encrypt([]byte(input), salt, key)
	if err != nil {
		return "", err
	}

	// Hash the secret content
	hash := hmac.New(sha256.New, key.hmacKey)
	hash.Write(data)
	hashSum := hash.Sum(nil)

	// Encode the secret payload
	return encodeSecret(&secret{data: data, salt: salt, hmac: hashSum}, key)
}

// Decrypt decrypts the input string with the vault password
func Decrypt(input string, password string) (string, error) {
	lines := strings.Split(input, "\n")
	if len(lines) < 2 {
		return "", errors.New("invalid secret format")
	}
	input = strings.Join(lines[1:], "\n")

	decoded, err := hexDecode(input)
	if err != nil {
		return "", err
	}

	secret, err := decodeSecret(decoded)
	if err != nil {
		return "", err
	}

	key := generateKey(password, secret.salt)
	if err := checkDigest(secret, key); err != nil {
		return "", err
	}

	result, err := decrypt(secret, key)
	if err != nil {
		return "", err
	}

	return result, nil
}

func DecryptFile(path string, password string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	return Decrypt(string(data), password)
}
