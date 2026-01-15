package stowry

import (
	"crypto/subtle"
	"net/url"
	"strconv"
	"time"
)

// Verifier validates Stowry presigned URL signatures.
//
// A Verifier is safe for concurrent use by multiple goroutines.
type Verifier struct {
	lookupKey func(accessKey string) (secretKey string, found bool)
}

// NewVerifier creates a Verifier with the given credential lookup function.
//
// The lookup function is called during verification to retrieve the secret key
// for a given access key. It should return the secret key and true if found,
// or an empty string and false if the access key is unknown.
//
// Example:
//
//	verifier := stowry.NewVerifier(func(accessKey string) (string, bool) {
//		secret, ok := credentialStore[accessKey]
//		return secret, ok
//	})
func NewVerifier(lookup func(accessKey string) (secretKey string, found bool)) *Verifier {
	return &Verifier{lookupKey: lookup}
}

// Verify validates a presigned URL signature.
//
// The method and path should match the HTTP request (e.g., "GET", "/bucket/file.txt").
// The query parameter should contain the URL query string parsed via [url.URL.Query].
//
// Returns nil if the signature is valid. Otherwise returns one of:
//   - [ErrMissingParams]: Required query parameters missing or malformed
//   - [ErrInvalidCredential]: Access key not found by lookup function
//   - [ErrExpired]: Signature validity period has elapsed
//   - [ErrInvalidSignature]: Signature does not match expected value
func (v *Verifier) Verify(method, path string, query url.Values) error {
	credential := query.Get(paramCredential)
	dateStr := query.Get(paramDate)
	expiresStr := query.Get(paramExpires)
	signature := query.Get(paramSignature)

	if credential == "" || dateStr == "" || expiresStr == "" || signature == "" {
		return ErrMissingParams
	}

	secretKey, found := v.lookupKey(credential)
	if !found {
		return ErrInvalidCredential
	}

	timestamp, err := strconv.ParseInt(dateStr, 10, 64)
	if err != nil {
		return ErrMissingParams
	}

	expires, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil {
		return ErrMissingParams
	}

	now := time.Now().Unix()
	if now > timestamp+expires {
		return ErrExpired
	}

	expected := sign(secretKey, method, path, timestamp, expires)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) != 1 {
		return ErrInvalidSignature
	}

	return nil
}
