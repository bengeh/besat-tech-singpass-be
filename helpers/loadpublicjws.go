package helpers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/square/go-jose/v3"
)

// LoadPublicJWSFromURL fetches the JWKS JSON and returns the first "sig" key
func LoadPublicJWSFromURL(jwksURL string) (jose.JSONWebKey, error) {
	resp, err := http.Get(jwksURL)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return jose.JSONWebKey{}, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("decode JWKS: %w", err)
	}

	for _, key := range jwks.Keys {
		if key.Use == "sig" {
			return key, nil
		}
	}

	return jose.JSONWebKey{}, fmt.Errorf("no signing key found in JWKS")
}
