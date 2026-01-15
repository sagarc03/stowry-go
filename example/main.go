package main

import (
	"fmt"
	"net/http"
	"net/url"

	stowry "github.com/sagarc03/stowry-go"
)

func main() {
	clientExample()
	serverExample()
}

func clientExample() {
	fmt.Println("=== Client Example ===")

	client := stowry.NewClient(
		"http://localhost:5708",
		"FE373CEF5632FDED3081",
		"9218d0ddfdb1779169f4b6b3b36df321099e98e9",
	)

	getURL := client.PresignGet("/files/document.pdf", 900)
	fmt.Println("GET URL:", getURL)

	putURL := client.PresignPut("/files/upload.txt", 900)
	fmt.Println("PUT URL:", putURL)

	deleteURL := client.PresignDelete("/files/old.txt", 900)
	fmt.Println("DELETE URL:", deleteURL)

	fmt.Println()
}

func serverExample() {
	fmt.Println("=== Server Example ===")

	keys := map[string]string{
		"FE373CEF5632FDED3081": "9218d0ddfdb1779169f4b6b3b36df321099e98e9",
	}

	verifier := stowry.NewVerifier(func(accessKey string) (string, bool) {
		secret, ok := keys[accessKey]
		return secret, ok
	})

	client := stowry.NewClient(
		"http://localhost:5708",
		"FE373CEF5632FDED3081",
		"9218d0ddfdb1779169f4b6b3b36df321099e98e9",
	)

	presignedURL := client.PresignGet("/files/test.txt", 900)
	parsed, _ := url.Parse(presignedURL)

	err := verifier.Verify("GET", parsed.Path, parsed.Query())
	if err != nil {
		fmt.Println("Verification failed:", err)
	} else {
		fmt.Println("Verification succeeded!")
	}

	fmt.Println()
	fmt.Println("To run as HTTP server, uncomment the code below and run:")
	fmt.Println("  go run example/main.go")

	// Uncomment to run as HTTP server:
	// http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 	if err := verifier.Verify(r.Method, r.URL.Path, r.URL.Query()); err != nil {
	// 		http.Error(w, err.Error(), http.StatusUnauthorized)
	// 		return
	// 	}
	// 	w.Write([]byte("OK"))
	// })
	// fmt.Println("Server listening on :8080")
	// http.ListenAndServe(":8080", nil)
}

var _ = http.ListenAndServe
