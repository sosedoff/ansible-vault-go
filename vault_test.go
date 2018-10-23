package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptDecrypt(t *testing.T) {
	result, err := Encrypt("test", "password")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)

	result, err = Decrypt(result, "password")
	assert.NoError(t, err)
	assert.Equal(t, "test", result)
}

func TestDecrypt(t *testing.T) {
	src := `$ANSIBLE_VAULT;1.1;AES256
63623566326538326634613931303733326439646130316566653930616264656431626135303933
6266626261373039363436353766613666356331653866310a303637623931666464326234616334
34303333663837316437613531383566633065333563616437356337643965336131376266366431
3031303331323232650a373739393962343137316261383931383436633262303661303537326462
3732`

	result, err := Decrypt(src, "password")
	assert.NoError(t, err)
	assert.Equal(t, "test\n", result)

	result, err = Decrypt(src, "invalid pass")
	assert.Equal(t, err.Error(), "invalid password")
	assert.Empty(t, result)

	result, err = Decrypt("invalid data", "password")
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "invalid secret format")

	result, err = Decrypt("$ANSIBLE_VAULT;1.1;AES256\n636235663265383266346139", "password")
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "invalid secret")
}
