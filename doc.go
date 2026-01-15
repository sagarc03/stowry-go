// Package stowry provides presigned URL generation and verification for Stowry.
//
// This is the reference implementation of the Stowry signing scheme. The Stowry
// server imports this package for signature verification.
//
// # Signing Scheme
//
// Stowry uses HMAC-SHA256 for request signing. Presigned URLs contain four
// query parameters:
//
//   - X-Stowry-Credential: Access key ID
//   - X-Stowry-Date: Unix timestamp in seconds
//   - X-Stowry-Expires: Validity period in seconds (1 to 604800)
//   - X-Stowry-Signature: Hex-encoded HMAC-SHA256 signature
//
// The signature is computed over a string with the format:
//
//	{METHOD}\n{PATH}\n{TIMESTAMP}\n{EXPIRES}
//
// # Client Usage
//
// Use [Client] to generate presigned URLs for accessing Stowry resources:
//
//	client := stowry.NewClient(
//		"https://storage.example.com",
//		"your-access-key",
//		"your-secret-key",
//	)
//
//	// Generate a presigned GET URL valid for 15 minutes
//	url := client.PresignGet("/bucket/object.pdf", 900)
//
// # Server Usage
//
// Use [Verifier] to validate presigned URLs on the server side:
//
//	verifier := stowry.NewVerifier(func(accessKey string) (string, bool) {
//		// Look up secret key from your credential store
//		return secretKey, found
//	})
//
//	err := verifier.Verify(r.Method, r.URL.Path, r.URL.Query())
//	if err != nil {
//		// Handle invalid signature
//	}
//
// # AWS Signature V4
//
// This package only implements the Stowry native signing scheme. For AWS
// Signature V4 compatibility, use the official aws-sdk-go-v2. The Stowry
// server supports both signing schemes.
package stowry
