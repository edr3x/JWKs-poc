package tokenize

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"

	"github.com/edr3x/go-jwks-rsa/internal/kv"
)

type TokenType string

const (
	Access  TokenType = "access"
	Refresh TokenType = "refresh"
)

type UserInfo struct {
	Id string `json:"user_id"`
}

type TokenClaims struct {
	Type TokenType `json:"token_type"`
	jwt.RegisteredClaims
	UserInfo
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var (
	keyStore  *kv.KeyValueStore
	signMap   = make(map[string]*rsa.PrivateKey)
	verifyMap = make(map[string]*rsa.PublicKey)
)

func init() {
	keyStore = kv.NewKeyValueStore()

	/*
	   To generate private key
	   $ openssl genrsa -out app.rsa 1024

	   Encode generated RSA to base64
	   $ cat app.rsa | base64 -w0
	*/
	keyEnvVars := []string{
		"RSA_PRIVATE_KEY1",
		"RSA_PRIVATE_KEY2",
		"RSA_PRIVATE_KEY3",
	}

	for _, envVar := range keyEnvVars {
		privateKey := loadPrivateKeyFromEnv(envVar)
		publicKey := &privateKey.PublicKey

		kid := generateDeterministicKid(publicKey)

		// map keys according to kid
		signMap[kid] = privateKey
		verifyMap[kid] = publicKey
	}
}

func Generate(tokenType TokenType, userId string) (string, error) {
	expirationTime := time.Now().Add(20 * time.Second)

	t := jwt.New(jwt.SigningMethodRS256)

	t.Claims = &TokenClaims{
		tokenType,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
		UserInfo{
			Id: userId,
		},
	}

	key, signKey := func() (string, *rsa.PrivateKey) {
		var keys []string
		for k := range signMap {
			keys = append(keys, k)
		}
		selectedKey := keys[rand.Intn(len(keys))]
		selectedSignKey := signMap[selectedKey]
		return selectedKey, selectedSignKey
	}()

	t.Header["kid"] = key

	return t.SignedString(signKey)
}

func VerifyToken(tokenType TokenType, tokenString string) (*UserInfo, error) {
	clms, err := VerifyTokenWithJwk(context.Background(), tokenString)
	if err != nil {
		return nil, err
	}

	if clms.Type != tokenType {
		return nil, fmt.Errorf("invalid token type")
	}

	return &clms.UserInfo, nil
}

func VerifyTokenWithJwk(ctx context.Context, tokenString string) (*TokenClaims, error) {
	jwkKeyUrl := []string{
		"http://localhost:8080/auth/keys",
	}

	k, err := keyfunc.NewDefaultCtx(ctx, jwkKeyUrl)
	if err != nil {
		return nil, err
	}

	var claims TokenClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, k.Keyfunc)
	if err != nil {
		return nil, err
	}

	if token.Method != jwt.SigningMethodRS256 {
		return nil, fmt.Errorf("invalid signing method")
	}

	if claims.ExpiresAt.Unix() <= time.Now().Unix() {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}
