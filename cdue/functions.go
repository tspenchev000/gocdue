package cdue

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// Encrypts plaintext using AES-GCM
func Encrypt(plaintext string, key []byte) (string, string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	nonce := make([]byte, 12) // AES-GCM standard nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(nonce), hex.EncodeToString(ciphertext), nil
}

// Decrypts AES-GCM encrypted ciphertext
func Decrypt(nonceHex, cipherHex string, key []byte) (string, error) {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("decryption failed")
	}

	return string(plaintext), nil
}

// Generates a token to update ciphertext without full decryption
func GenerateUpdateToken(oldKey, newKey []byte) []byte {
	h := hmac.New(sha256.New, oldKey)
	h.Write(newKey)
	return h.Sum(nil) // Token = HMAC(oldKey, newKey)
}

// Updates ciphertext using the update token
func UpdateCiphertext(oldKey, newKey []byte, nonceHex, cipherHex string) (string, string, error) {
	token := GenerateUpdateToken(oldKey, newKey)
	block, err := aes.NewCipher(token) // Use token to create a pseudo-key
	if err != nil {
		return "", "", err
	}

	ciphertext, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", "", err
	}

	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	newCiphertext := aesGCM.Seal(nil, nonce, ciphertext, nil) // Transform ciphertext
	return nonceHex, hex.EncodeToString(newCiphertext), nil
}

// Generates a random AES key
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256 key size
	_, err := rand.Read(key)
	return key, err
}
