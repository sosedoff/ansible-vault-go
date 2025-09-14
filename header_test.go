package vault

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_parseHeader(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *header
		err      error
	}{
		{
			name:     "empty input",
			input:    "",
			expected: nil,
			err:      ErrInvalidFormat,
		},
		{
			name:     "not an ansible format",
			input:    "some text",
			expected: nil,
			err:      ErrInvalidFormat,
		},
		{
			name:     "invalid header format",
			input:    "FOO;BAR;some;data",
			expected: nil,
			err:      ErrInvalidFormat,
		},
		{
			name:     "incomplete header",
			input:    "$ANSIBLE_VAULT;;",
			expected: nil,
			err:      ErrInvalidFormat,
		},
		{
			name:     "unsupported version",
			input:    "$ANSIBLE_VAULT;1.0;AES256",
			expected: nil,
			err:      ErrInvalidFormat,
		},
		{
			name:     "unsupported version 2",
			input:    "$ANSIBLE_VAULT;1.2;AES256",
			expected: nil,
			err:      ErrInvalidFormat,
		},
		{
			name:     "unsupported cipher",
			input:    "$ANSIBLE_VAULT;1.1;AES",
			expected: nil,
			err:      ErrInvalidFormat,
		},
		{
			name:     "supported version and cipher",
			input:    "$ANSIBLE_VAULT;1.1;AES256\n",
			expected: &header{version: "1.1", cipher: "AES256", label: ""},
			err:      nil,
		},
		{
			name:     "with label",
			input:    "$ANSIBLE_VAULT;1.1;AES256;label\n",
			expected: &header{version: "1.1", cipher: "AES256", label: "label"},
			err:      nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			head, err := parseHeader(test.input)

			require.Equal(tt, test.err, err)
			require.Equal(tt, test.expected, head)
		})
	}
}

func TestHeaderString(t *testing.T) {
	head := header{}
	require.Equal(t, "$ANSIBLE_VAULT;;", head.String())

	head.version = "1.1"
	head.cipher = "AES256"
	require.Equal(t, "$ANSIBLE_VAULT;1.1;AES256", head.String())

	head.label = "label"
	require.Equal(t, "$ANSIBLE_VAULT;1.1;AES256;label", head.String())
}
