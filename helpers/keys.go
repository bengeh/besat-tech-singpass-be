package helpers

import (
	"encoding/json"
	"fmt"
	"os"

	jose "github.com/square/go-jose/v3"
)

// LoadJWKFromFile loads a single JWK (private key) or a JWK set
func LoadJWKFromFile(path string) (jose.JSONWebKey, error) {
	var raw interface{}
	f, err := os.ReadFile(path)
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	if err := json.Unmarshal(f, &raw); err != nil {
		return jose.JSONWebKey{}, err
	}

	// If file contains a single JWK object
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(f, &jwk); err == nil && jwk.Key != nil {
		return jwk, nil
	}

	// Else try as JWK set
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(f, &set); err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("invalid jwk or jwks file")
	}
	if len(set.Keys) == 0 {
		return jose.JSONWebKey{}, fmt.Errorf("jwks contains no keys")
	}
	return set.Keys[0], nil
}

// LoadJWKSetFromFile returns a jose.JSONWebKeySet
func LoadJWKSetFromFile(path string) (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	b, err := os.ReadFile(path)
	if err != nil {
		return set, err
	}
	if err := json.Unmarshal(b, &set); err != nil {
		return set, err
	}
	return set, nil
}
