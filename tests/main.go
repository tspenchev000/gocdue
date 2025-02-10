package main

import (
	"fmt"

	"github.com/tspenchev000/gocdue/cdue"
)

func main() {
	// Generate initial key
	key1, _ := cdue.GenerateKey()
	fmt.Printf("Original Key: %x\n", key1)

	// Encrypt data
	nonce, ciphertext, _ := cdue.Encrypt("Sensitive Data", key1)
	fmt.Printf("Encrypted: Nonce: %s, Ciphertext: %s\n", nonce, ciphertext)

	// Decrypt data
	plaintext, _ := cdue.Decrypt(nonce, ciphertext, key1)
	fmt.Printf("Decrypted: %s\n", plaintext)

	// Generate new key and update token
	key2, _ := cdue.GenerateKey()
	fmt.Printf("New Key: %x\n", key2)

	token := cdue.GenerateUpdateToken(key1, key2)
	fmt.Printf("Update Token: %x\n", token)

	// Update ciphertext
	newNonce, newCipher, _ := cdue.UpdateCiphertext(key1, key2, nonce, ciphertext)
	fmt.Printf("Updated Encrypted: Nonce: %s, Ciphertext: %s\n", newNonce, newCipher)

	// Decrypt with updated key
	updatedPlaintext, _ := cdue.Decrypt(newNonce, newCipher, key2)
	fmt.Printf("Decrypted after Update: %s\n", updatedPlaintext)
}
