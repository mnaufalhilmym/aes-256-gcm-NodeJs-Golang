package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"log"
)

func generateRandomKey() []byte {
	randomKey := make([]byte, 32)
	if _, err := rand.Read(randomKey); err != nil {
		log.Fatalln(err)
	}
	return randomKey
}

func generateRandomNonce() []byte {
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalln(err)
	}
	return nonce
}

func Encrypt(plain string) (map[string]string, error) {
	// If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key := generateRandomKey()
	plainText := []byte(plain)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := generateRandomNonce()

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	cipherText := aesgcm.Seal(nil, nonce, plainText, nil)

	return map[string]string{"encKey": base64.RawURLEncoding.EncodeToString(key), "encCipherText": base64.RawURLEncoding.EncodeToString(cipherText[:len(cipherText)-16]), "encAuthTag": base64.RawURLEncoding.EncodeToString(cipherText[len(cipherText)-16:]), "encNonce": base64.RawURLEncoding.EncodeToString(nonce)}, nil
}

func Decrypt(encrypted map[string]string) (string, error) {
	// If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).

	key, err := base64.RawURLEncoding.DecodeString(encrypted["encKey"])
	if err != nil {
		return "", err
	}
	cipherText, err := base64.RawURLEncoding.DecodeString(encrypted["encCipherText"])
	if err != nil {
		return "", err
	}
	authTag, err := base64.RawURLEncoding.DecodeString(encrypted["encAuthTag"])
	if err != nil {
		return "", err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(encrypted["encNonce"])
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plainText, err := aesgcm.Open(nil, nonce, append(cipherText, authTag...), nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
