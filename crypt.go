package vault

import (
	"crypto/aes"
	"crypto/cipher"
)

func encrypt(data []byte, salt []byte, key *key) ([]byte, error) {
	bs := aes.BlockSize
	padding := (bs - len(data)%bs)
	if padding == 0 {
		padding = bs
	}
	padChar := rune(padding)
	padArray := make([]byte, padding)
	for i := range padArray {
		padArray[i] = byte(padChar)
	}

	plaintext := []byte(data)
	plaintext = append(plaintext, padArray...)

	aesCipher, err := aes.NewCipher(key.cipherKey)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))

	aesBlock := cipher.NewCTR(aesCipher, key.iv)
	aesBlock.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

func decrypt(secret *secret, key *key) (string, error) {
	aesCipher, err := aes.NewCipher(key.cipherKey)
	if err != nil {
		return "", err
	}
	aesBlock := cipher.NewCTR(aesCipher, key.iv)
	plainText := make([]byte, len(secret.data))

	aesBlock.XORKeyStream(plainText, secret.data)

	padding := int(plainText[len(plainText)-1])
	result := string(plainText[:len(plainText)-padding])

	return string(result), nil
}
