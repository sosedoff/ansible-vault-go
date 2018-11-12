package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io/ioutil"
	"strings"
)

var (
	// ErrInvalidFormat is returned when secret content is not valid
	ErrInvalidFormat = errors.New("invalid secret format")
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

// EncryptFile encrypts the input string and saves it into the file
func EncryptFile(path string, input string, password string) error {
	result, err := Encrypt(input, password)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, []byte(result), 0666)
}

// Decrypt decrypts the input string with the vault password
func Decrypt(input string, password string) (string, error) {
	lines := strings.Split(input, "\n")

	// Valid secret must include header and body
	if len(lines) < 2 {
		return "", ErrInvalidFormat
	}

	// Validate the vault file format
	if strings.TrimSpace(lines[0]) != vaultHeader {
		return "", ErrInvalidFormat
	}

	decoded, err := hexDecode(strings.Join(lines[1:], "\n"))
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

// DecryptFile decrypts the content of the file with the vault password
func DecryptFile(path string, password string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	return Decrypt(string(data), password)
}
