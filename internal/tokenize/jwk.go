package tokenize

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
)

type JWKs struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use,omitempty"`
}

func GetJwkKeys() (res JWKs, err error) {
	cacheKey := "jwk_cache"

	response, ok := keyStore.Get(cacheKey)
	if ok {
		if err := json.Unmarshal([]byte(response), &res); err == nil {
			return res, nil
		}
	}

	for key, v := range verifyMap {
		jwk, err := encodeToJWK(v, key)
		if err != nil {
			slog.Error("JWK Encoding Error", "error: ", err.Error())
			continue
		}
		res.Keys = append(res.Keys, jwk)
	}

	val, err := json.Marshal(res)
	if err != nil {
		slog.Error("Key Marshalling Error", "error: ", err.Error())
		return res, nil
	}
	keyStore.Set(cacheKey, string(val))

	return res, nil
}

func encodeToJWK(rsaPubKey *rsa.PublicKey, kid string) (JWK, error) {
	n := base64.RawURLEncoding.EncodeToString(rsaPubKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPubKey.E)).Bytes())

	jwk := JWK{
		Kty: "RSA",
		Alg: "RS256",
		Kid: kid,
		N:   n,
		E:   e,
		Use: "sig",
	}

	return jwk, nil
}
