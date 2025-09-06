package vault

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncrypt(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		password string
		err      error
		match    string
	}{
		{name: "empty password", password: "", err: ErrEmptyPassword},
		{name: "empty input", password: "password", match: "$ANSIBLE_VAULT;1.1;AES256"},
		{name: "success", input: "test", password: "password", match: "$ANSIBLE_VAULT;1.1;AES256"},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			result, err := Encrypt(test.input, test.password)

			if test.err != nil {
				assert.Error(tt, test.err, err)
				assert.Contains(tt, err.Error(), test.err.Error())
				return
			}

			assert.NoError(tt, err)
			assert.Contains(tt, result, test.match)
		})
	}
}

func TestEncryptFile(t *testing.T) {
	t.Run("file does not exist", func(t *testing.T) {
		err := EncryptFile("/path/to/file", "input", "password")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("empty password", func(t *testing.T) {
		err := EncryptFile("/path/to/file", "input", "")
		assert.Equal(t, ErrEmptyPassword, err)
	})

	t.Run("path exists", func(t *testing.T) {
		outPath := "/tmp/encrypt"

		t.Cleanup(func() {
			os.Remove(outPath)
		})

		err := EncryptFile(outPath, "input", "password")
		assert.NoError(t, err)
		assert.FileExists(t, outPath)

		content, err := os.ReadFile(outPath)
		assert.NoError(t, err)
		assert.Contains(t, string(content), "$ANSIBLE_VAULT;1.1;AES256")
	})
}

func TestDecrypt(t *testing.T) {
	sample := `$ANSIBLE_VAULT;1.1;AES256
66636665376466363035323339653038313631366530366139353930363639396263336538656638
3232656465323265663737633039363037323039393039620a303065353563633261633964623139
32363666633230313364356230623830383134383432633932333630626462316434333137373131
6362373633313532650a313362613134656433663238333163323865666237366161366164383266
3936`

	empty := `$ANSIBLE_VAULT;1.1;AES256
62613733343936633739383863623438363535336535643539623734313533663838643661313230
6231343261616531393039313562663037303566356437370a643965616335653166653032656566
37646235336630613233633233396136636434303338373563366237383939616361313638376434
6464623462326236650a663235666338633036633336303632343834633164323537333030363061
3163`

	tests := []struct {
		name     string
		input    string
		password string
		err      error
		match    string
	}{
		{name: "success", input: sample, password: "password", match: "test\n"},
		{name: "invalid password", input: sample, password: "invalid pass", err: errors.New("invalid password")},
		{name: "invalid input", input: "invalid data", password: "password", err: ErrInvalidFormat},
		{name: "invalid secret format", input: "$ANSIBLE_VAULT;2.0;AES256\n636235663265383266346139", password: "password", err: ErrInvalidFormat},
		{name: "invalid secret input", input: "$ANSIBLE_VAULT;1.1;AES256\n636235663265383266346139", password: "password", err: errors.New("invalid secret")},
		{name: "empty password", input: empty, password: "", err: ErrEmptyPassword},
		{name: "empty input", input: empty, password: "password", match: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			result, err := Decrypt(test.input, test.password)

			if test.err != nil {
				assert.Error(tt, test.err, err)
				assert.Contains(tt, err.Error(), test.err.Error())
				return
			}

			assert.NoError(tt, err)
			assert.Contains(tt, result, test.match)
		})
	}
}

func TestDecryptFile(t *testing.T) {
	t.Run("invalid path", func(t *testing.T) {
		content, err := DecryptFile("/tmp/foo", "password")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
		assert.Equal(t, "", content)
	})

	t.Run("file exists", func(t *testing.T) {
		inPath := "/tmp/decrypt"
		raw := `$ANSIBLE_VAULT;1.1;AES256
66636665376466363035323339653038313631366530366139353930363639396263336538656638
3232656465323265663737633039363037323039393039620a303065353563633261633964623139
32363666633230313364356230623830383134383432633932333630626462316434333137373131
6362373633313532650a313362613134656433663238333163323865666237366161366164383266
3936`

		err := os.WriteFile(inPath, []byte(raw), 0666)
		assert.NoError(t, err)

		content, err := DecryptFile(inPath, "password")
		assert.Nil(t, err)
		assert.Equal(t, "test\n", content)
	})
}

func TestEncryptDecrypt(t *testing.T) {
	result, err := Encrypt("test\n", "password")
	assert.NoError(t, err)
	assert.Contains(t, result, "$ANSIBLE_VAULT;1.1;AES256")

	result, err = Decrypt(result, "password")
	assert.NoError(t, err)
	assert.Equal(t, "test\n", result)
}
