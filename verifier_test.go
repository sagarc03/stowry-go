package stowry

import (
	"errors"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func testLookup(accessKey string) (string, bool) {
	keys := map[string]string{
		"FE373CEF5632FDED3081": "9218d0ddfdb1779169f4b6b3b36df321099e98e9",
		"testkey":              "testsecret",
	}
	secret, ok := keys[accessKey]
	return secret, ok
}

func TestVerifierValid(t *testing.T) {
	v := NewVerifier(testLookup)

	timestamp := time.Now().Unix()
	expires := int64(900)
	sig := Sign("testsecret", "GET", "/test/file.txt", timestamp, expires)

	query := url.Values{}
	query.Set(StowryCredentialParam, "testkey")
	query.Set(StowryDateParam, strconv.FormatInt(timestamp, 10))
	query.Set(StowryExpiresParam, strconv.FormatInt(expires, 10))
	query.Set(StowrySignatureParam, sig)

	err := v.Verify("GET", "/test/file.txt", query)
	if err != nil {
		t.Errorf("Verify() = %v, want nil", err)
	}
}

func TestVerifierMissingParams(t *testing.T) {
	v := NewVerifier(testLookup)

	tests := []struct {
		name  string
		query url.Values
	}{
		{"missing credential", url.Values{
			StowryDateParam: {"123"}, StowryExpiresParam: {"900"}, StowrySignatureParam: {"abc"},
		}},
		{"missing date", url.Values{
			StowryCredentialParam: {"key"}, StowryExpiresParam: {"900"}, StowrySignatureParam: {"abc"},
		}},
		{"missing expires", url.Values{
			StowryCredentialParam: {"key"}, StowryDateParam: {"123"}, StowrySignatureParam: {"abc"},
		}},
		{"missing signature", url.Values{
			StowryCredentialParam: {"key"}, StowryDateParam: {"123"}, StowryExpiresParam: {"900"},
		}},
		{"empty query", url.Values{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Verify("GET", "/test", tt.query)
			if !errors.Is(err, ErrMissingParams) {
				t.Errorf("Verify() = %v, want ErrMissingParams", err)
			}
		})
	}
}

func TestVerifierInvalidCredential(t *testing.T) {
	v := NewVerifier(testLookup)

	query := url.Values{}
	query.Set(StowryCredentialParam, "unknownkey")
	query.Set(StowryDateParam, "1736956800")
	query.Set(StowryExpiresParam, "900")
	query.Set(StowrySignatureParam, "somesig")

	err := v.Verify("GET", "/test", query)
	if !errors.Is(err, ErrInvalidCredential) {
		t.Errorf("Verify() = %v, want ErrInvalidCredential", err)
	}
}

func TestVerifierExpired(t *testing.T) {
	v := NewVerifier(testLookup)

	oldTimestamp := time.Now().Unix() - 1000
	expires := int64(900)
	sig := Sign("testsecret", "GET", "/test", oldTimestamp, expires)

	query := url.Values{}
	query.Set(StowryCredentialParam, "testkey")
	query.Set(StowryDateParam, strconv.FormatInt(oldTimestamp, 10))
	query.Set(StowryExpiresParam, strconv.FormatInt(expires, 10))
	query.Set(StowrySignatureParam, sig)

	err := v.Verify("GET", "/test", query)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("Verify() = %v, want ErrExpired", err)
	}
}

func TestVerifierInvalidSignature(t *testing.T) {
	v := NewVerifier(testLookup)

	timestamp := time.Now().Unix()
	expires := int64(900)

	query := url.Values{}
	query.Set(StowryCredentialParam, "testkey")
	query.Set(StowryDateParam, strconv.FormatInt(timestamp, 10))
	query.Set(StowryExpiresParam, strconv.FormatInt(expires, 10))
	query.Set(StowrySignatureParam, "invalidsignature")

	err := v.Verify("GET", "/test", query)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify() = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifierTestVector(t *testing.T) {
	v := NewVerifier(testLookup)

	query := url.Values{}
	query.Set(StowryCredentialParam, "FE373CEF5632FDED3081")
	query.Set(StowryDateParam, "1736956800")
	query.Set(StowryExpiresParam, "900")
	query.Set(StowrySignatureParam, "b24285352583edb3d06c531f61e38c5706d42d79e31474bf1f95667d524bae21")

	err := v.Verify("GET", "/test/hello.txt", query)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("Test vector with old timestamp should be expired, got %v", err)
	}
}

func TestVerifierInvalidDateFormat(t *testing.T) {
	v := NewVerifier(testLookup)

	query := url.Values{}
	query.Set(StowryCredentialParam, "testkey")
	query.Set(StowryDateParam, "not-a-number")
	query.Set(StowryExpiresParam, "900")
	query.Set(StowrySignatureParam, "somesig")

	err := v.Verify("GET", "/test", query)
	if !errors.Is(err, ErrMissingParams) {
		t.Errorf("Verify() = %v, want ErrMissingParams for invalid date", err)
	}
}

func TestVerifierInvalidExpiresFormat(t *testing.T) {
	v := NewVerifier(testLookup)

	query := url.Values{}
	query.Set(StowryCredentialParam, "testkey")
	query.Set(StowryDateParam, "1736956800")
	query.Set(StowryExpiresParam, "not-a-number")
	query.Set(StowrySignatureParam, "somesig")

	err := v.Verify("GET", "/test", query)
	if !errors.Is(err, ErrMissingParams) {
		t.Errorf("Verify() = %v, want ErrMissingParams for invalid expires", err)
	}
}

func TestClientVerifierRoundTrip(t *testing.T) {
	client := NewClient("http://localhost:5708", "testkey", "testsecret")
	verifier := NewVerifier(testLookup)

	presignedURL := client.PresignGet("/files/document.pdf", 900)

	parsed, err := url.Parse(presignedURL)
	if err != nil {
		t.Fatalf("Failed to parse presigned URL: %v", err)
	}

	err = verifier.Verify("GET", parsed.Path, parsed.Query())
	if err != nil {
		t.Errorf("Round trip verification failed: %v", err)
	}
}
