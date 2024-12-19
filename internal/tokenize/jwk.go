package tokenize

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"

	"github.com/MicahParks/jwkset"
)

func GetJwkKeys() (res jwkset.JWKSMarshal, err error) {
	cacheKey := "jwk_cache"

	response, ok := keyStore.Get(cacheKey)
	if ok {
		if err := json.Unmarshal([]byte(response), &res); err == nil {
			return res, nil
		}
	}

	for key, v := range verifyMap {
		jwk := encodeToJWK(v, key)
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

func encodeToJWK(rsaPubKey *rsa.PublicKey, kid string) jwkset.JWKMarshal {
	n := base64.RawURLEncoding.EncodeToString(rsaPubKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPubKey.E)).Bytes())
	return jwkset.JWKMarshal{
		KTY: jwkset.KtyRSA,
		ALG: jwkset.AlgRS256,
		KID: kid,
		N:   n,
		E:   e,
		USE: jwkset.UseSig,
	}
}
