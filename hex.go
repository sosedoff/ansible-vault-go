package vault

import (
	"encoding/hex"
	"strings"
)

func hexDecode(input string) (string, error) {
	input = strings.TrimSpace(input)
	input = strings.Replace(input, "\r", "", -1)
	input = strings.Replace(input, "\n", "", -1)

	decoded, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}
