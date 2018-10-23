# ansible-vault-go

Go package to read/write Ansible Vault secrets

## Installation

```
go get github.com/sosedoff/ansible-vault-go
```

## Usage

```go
package main

import(
  "log"

  "github.com/sosedoff/ansible-vault-go"
)

func main() {
  // Encrypt secret data
  str, err := vault.Encrypt("secret", "password")

  // Decrypt secret data
  str, err := vault.Decrypt("secret", "password")

  // Write secret data to file
  err := vault.EncryptFile("path/to/secret/file", "secret", "password")

  // Read existing secret
  str, err := vault.DecryptFile("path/to/secret/file", "password")
}
```

## License

MIT