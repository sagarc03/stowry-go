package main

import (
	"fmt"

	stowry "github.com/sagarc03/stowry-go"
)

func main() {
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
}
