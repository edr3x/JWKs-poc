package tokenize

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"os"

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

func generateDeterministicKid(publicKey *rsa.PublicKey) string {
	pubKeyBytes := append(publicKey.N.Bytes(), byte(publicKey.E))
	hash := sha256.Sum256(pubKeyBytes)
	return hex.EncodeToString(hash[:12])
}
