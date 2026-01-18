package stowry

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	// DefaultExpires is the default validity period in seconds (15 minutes).
	DefaultExpires = 900
	// MaxExpires is the maximum validity period in seconds (7 days).
	MaxExpires = 604800

	// StowryCredentialHeader is the query parameter name for the access key ID.
	StowryCredentialHeader = "X-Stowry-Credential" //nolint:gosec // query parameter name, not a credential
	// StowryDateHeader is the query parameter name for the Unix timestamp.
	StowryDateHeader = "X-Stowry-Date"
	// StowryExpiresHeader is the query parameter name for the validity period in seconds.
	StowryExpiresHeader = "X-Stowry-Expires"
	// StowrySignatureHeader is the query parameter name for the HMAC-SHA256 signature.
	StowrySignatureHeader = "X-Stowry-Signature"
)

// Sign generates an HMAC-SHA256 signature for the given parameters.
//
// The signature is computed over a string in the format:
//
//	{METHOD}\n{PATH}\n{TIMESTAMP}\n{EXPIRES}
//
// Returns the hex-encoded HMAC-SHA256 signature.
func Sign(secretKey, method, path string, timestamp, expires int64) string {
	stringToSign := fmt.Sprintf("%s\n%s\n%d\n%d", method, path, timestamp, expires)
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(stringToSign))
	return hex.EncodeToString(h.Sum(nil))
}
