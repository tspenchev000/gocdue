package main

//require "github.com/tspenchev000/gocdue/cdue"

import (
	"fmt"
)

func main() {
	// Generate initial key
	key1, _ := cdue.generateKey()
	fmt.Printf("Original Key: %x\n", key1)

	// Encrypt data
	nonce, ciphertext, _ := encrypt("Sensitive Data", key1)
	fmt.Printf("Encrypted: Nonce: %s, Ciphertext: %s\n", nonce, ciphertext)

	// Decrypt data
	plaintext, _ := decrypt(nonce, ciphertext, key1)
	fmt.Printf("Decrypted: %s\n", plaintext)

	// Generate new key and update token
	key2, _ := generateKey()
	fmt.Printf("New Key: %x\n", key2)

	token := generateUpdateToken(key1, key2)
	fmt.Printf("Update Token: %x\n", token)

	// Update ciphertext
	newNonce, newCipher, _ := updateCiphertext(key1, key2, nonce, ciphertext)
	fmt.Printf("Updated Encrypted: Nonce: %s, Ciphertext: %s\n", newNonce, newCipher)

	// Decrypt with updated key
	updatedPlaintext, _ := decrypt(newNonce, newCipher, key2)
	fmt.Printf("Decrypted after Update: %s\n", updatedPlaintext)
}
