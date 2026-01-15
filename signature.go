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

	paramCredential = "X-Stowry-Credential" //nolint:gosec // query parameter name, not a credential
	paramDate       = "X-Stowry-Date"
	paramExpires    = "X-Stowry-Expires"
	paramSignature  = "X-Stowry-Signature"
)

// sign generates an HMAC-SHA256 signature for the given parameters.
func sign(secretKey, method, path string, timestamp, expires int64) string {
	stringToSign := fmt.Sprintf("%s\n%s\n%d\n%d", method, path, timestamp, expires)
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(stringToSign))
	return hex.EncodeToString(h.Sum(nil))
}
