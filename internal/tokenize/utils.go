package tokenize

import (
	"crypto/rsa"
	"encoding/base64"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func loadPrivateKeyFromEnv(envVar string) *rsa.PrivateKey {
	// Retrieve the private key from the environment
	encodedKey, ok := os.LookupEnv(envVar)
	if !ok {
		log.Fatalf("%s not provided", envVar)
	}

	// Decode the base64-encoded private key
	keyBytes, err := base64.StdEncoding.DecodeString(encodedKey)
	fatal(err)

	// Parse the RSA private key from PEM format
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	fatal(err)

	return privateKey
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(length int) string {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}
