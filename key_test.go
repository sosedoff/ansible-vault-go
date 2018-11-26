package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_generateKey(t *testing.T) {
	key := generateKey([]byte("password"), []byte("salt"))

	assert.Len(t, key.cipherKey, keyLength)
	assert.Len(t, key.hmacKey, keyLength)
	assert.Len(t, key.iv, ivLength)
}
