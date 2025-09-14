package vault

import (
	"strings"
)

const (
	headerFormat    = "$ANSIBLE_VAULT" // Magic header ID
	headerParts     = 3                // Required number of parts in the header
	headerSeparator = ";"              // Separator used in the header
)

var (
	// headerVersions defines a set of supported vault format versions
	headerVersions = map[string]bool{
		"1.0": false,
		"1.1": true,
		"1.2": false,
	}

	// headerCiphers defines a set of supported vault ciphers
	headerCiphers = map[string]bool{
		"AES256": true,
	}

	// defaultHeader is the default header used for encoding and decoding vault data
	defaultHeader = header{
		version: "1.1",
		cipher:  "AES256",
	}
)

// header represents the vault header and format details
// refer to ansible documentation for details: https://docs.ansible.com/ansible/2.8/user_guide/vault.html#vault-format
type header struct {
	version string
	cipher  string
	label   string
}

// String returns the vault header text representation
func (h header) String() string {
	parts := []string{
		headerFormat,
		h.version,
		h.cipher,
	}

	if h.label != "" {
		parts = append(parts, h.label)
	}

	return strings.Join(parts, headerSeparator)
}

// Validate checks if all header values are correct
func (h header) Validate() error {
	if !headerVersions[h.version] {
		return ErrInvalidFormat
	}

	if !headerCiphers[h.cipher] {
		return ErrInvalidFormat
	}

	return nil
}

// parseHeader returns an ansible vault header details or an error if it's invalid
func parseHeader(input string) (*header, error) {
	parts := strings.SplitN(strings.TrimSpace(input), headerSeparator, 4)

	// Ensure the vault header format conforms to "$FORMAT;VERSION;CIPHER"
	if len(parts) < headerParts {
		return nil, ErrInvalidFormat
	}

	if parts[0] != headerFormat {
		return nil, ErrInvalidFormat
	}

	parts = parts[1:]

	head := header{
		version: parts[0],
		cipher:  parts[1],
	}

	if len(parts) >= 3 {
		head.label = parts[2]
	}

	err := head.Validate()
	if err != nil {
		return nil, err
	}

	return &head, nil
}
