# stowry-go

[![CI](https://github.com/sagarc03/stowry-go/actions/workflows/ci.yml/badge.svg)](https://github.com/sagarc03/stowry-go/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/sagarc03/stowry-go)](https://goreportcard.com/report/github.com/sagarc03/stowry-go)

Go SDK for [Stowry](https://github.com/sagarc03/stowry) presigned URL generation and signature verification.

## Installation

```bash
go get github.com/sagarc03/stowry-go
```

## Usage

### Client (Generating Presigned URLs)

```go
package main

import (
    "fmt"
    stowry "github.com/sagarc03/stowry-go"
)

func main() {
    client := stowry.NewClient(
        "http://localhost:5708",
        "your-access-key",
        "your-secret-key",
    )

    // Generate presigned GET URL (valid for 15 minutes)
    getURL := client.PresignGet("/files/document.pdf", 900)
    fmt.Println(getURL)

    // Generate presigned PUT URL
    putURL := client.PresignPut("/files/upload.txt", 900)

    // Generate presigned DELETE URL
    deleteURL := client.PresignDelete("/files/old.txt", 900)
}
```

### Server (Verifying Signatures)

```go
package main

import (
    "net/http"
    stowry "github.com/sagarc03/stowry-go"
)

func main() {
    verifier := stowry.NewVerifier(func(accessKey string) (string, bool) {
        // Look up secret key by access key from your database
        keys := map[string]string{
            "your-access-key": "your-secret-key",
        }
        secret, ok := keys[accessKey]
        return secret, ok
    })

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        if err := verifier.Verify(r.Method, r.URL.Path, r.URL.Query()); err != nil {
            http.Error(w, err.Error(), http.StatusUnauthorized)
            return
        }
        w.Write([]byte("OK"))
    })

    http.ListenAndServe(":8080", nil)
}
```

### Low-Level Signing

```go
// Generate a signature directly
signature := stowry.Sign(
    "your-secret-key",
    "GET",
    "/bucket/object.pdf",
    1736956800,  // Unix timestamp
    900,         // Expires in seconds
)
```

## Constants

```go
stowry.DefaultExpires          // 900 (15 minutes)
stowry.MaxExpires              // 604800 (7 days)
stowry.StowryCredentialParam   // "X-Stowry-Credential"
stowry.StowryDateParam         // "X-Stowry-Date"
stowry.StowryExpiresParam      // "X-Stowry-Expires"
stowry.StowrySignatureParam    // "X-Stowry-Signature"
```

## Errors

```go
stowry.ErrMissingParams     // Missing required signature parameters
stowry.ErrExpired           // Signature expired
stowry.ErrInvalidCredential // Unknown access key
stowry.ErrInvalidSignature  // Signature mismatch
```

## Signing Scheme

Query parameters:

- `X-Stowry-Credential` - Access key ID
- `X-Stowry-Date` - Unix timestamp (seconds)
- `X-Stowry-Expires` - Validity in seconds (1-604800)
- `X-Stowry-Signature` - Hex-encoded HMAC-SHA256

String to sign:

```text
{METHOD}\n{PATH}\n{TIMESTAMP}\n{EXPIRES}
```

## License

See [LICENSE](LICENSE) file.
