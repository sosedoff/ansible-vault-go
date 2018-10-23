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
  // Define vault password
  pass := "secret"
  
  // Read existing secret
  str, err := vault.DecryptFile("path/to/secret/file", pass)

  // Decrypt from string
  str, err := vault.Decrypt("secret data", pass)
}
```

## License

MIT