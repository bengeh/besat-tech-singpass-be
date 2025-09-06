package config

import (
	"encoding/json"
	"os"
)

type KeysConfig struct {
	PrivateSigPath string `json:"PRIVATE_SIG_KEY"`
	PrivateEncPath string `json:"PRIVATE_ENC_KEY"`
	PublicJwksPath string `json:"PUBLIC_JWKS"`
}

type Config struct {
	ClientID    string     `json:"CLIENT_ID"`
	IssuerURL   string     `json:"ISSUER_URL"`
	RedirectURI string     `json:"REDIRECT_URI"`
	Scopes      string     `json:"SCOPES"`
	Keys        KeysConfig `json:"KEYS"`

	// keep your DB fields too if needed (left out for brevity)
}

func LoadFromFile(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	err = dec.Decode(&cfg)
	return cfg, err
}
