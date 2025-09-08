package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"crypto/rand"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	jose "github.com/square/go-jose/v3"

	"beast-tech-singpass-be/config"
	"beast-tech-singpass-be/helpers"
)

// SingpassHandler holds runtime data
type SingpassHandler struct {
	Config           config.Config
	PrivateSig       jose.JSONWebKey // private signing JWK (ES256)
	PrivateEnc       jose.JSONWebKey // private encryption JWK (ECDH-ES) optional
	PublicJWKS       jose.JSONWebKeySet
	Provider         *oidc.Provider
	Verifier         *oidc.IDTokenVerifier
	AuthEndpoint     string
	TokenEndpoint    string
	UserinfoEndpoint string
}

// NewSingpassHandler creates and initializes discovery and verifiers
func NewSingpassHandler(cfg config.Config) (*SingpassHandler, error) {
	s := &SingpassHandler{Config: cfg}

	// load keys
	sig, err := helpers.LoadJWKFromFile(cfg.Keys.PrivateSigPath)
	if err != nil {
		return nil, fmt.Errorf("load sig key: %w", err)
	}
	s.PrivateSig = sig

	enc, err := helpers.LoadJWKFromFile(cfg.Keys.PrivateEncPath)
	if err == nil {
		s.PrivateEnc = enc
	} // encryption key optional

	pub, err := helpers.LoadJWKSetFromFile(cfg.Keys.PublicJwksPath)
	if err != nil {
		return nil, fmt.Errorf("load public jwks: %w", err)
	}
	s.PublicJWKS = pub

	// discover issuer
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("issuer discovery: %w", err)
	}
	s.Provider = provider

	// get endpoints from provider's metadata
	var meta map[string]interface{}
	if err := provider.Claims(&meta); err == nil {
		if auth, ok := meta["authorization_endpoint"].(string); ok {
			s.AuthEndpoint = auth
		}
		if token, ok := meta["token_endpoint"].(string); ok {
			s.TokenEndpoint = token
		}
		if ui, ok := meta["userinfo_endpoint"].(string); ok {
			s.UserinfoEndpoint = ui
		}
	}

	// ID token verifier using provider keys; use clientID as audience
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	s.Verifier = verifier

	return s, nil
}

func base64URLEncodeNoPad(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func generateCodeVerifier() (string, error) {
	// 32 bytes ~ 43 chars after base64 URL encoding
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	// Base64 URL encode without padding
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	// Base64 URL encode without padding
	s := base64.RawURLEncoding.EncodeToString(b)

	// Trim or pad to exact length
	if len(s) >= n {
		return s[:n], nil
	}
	return s, nil
}

// BuildAuthURL builds authorization URL with PKCE S256, nonce, state
func (h *SingpassHandler) BuildAuthURL(c *gin.Context) (authURL string, codeVerifier string, state string, nonce string, err error) {
	codeVerifier, err = generateCodeVerifier() // replace with secure crypto/rand
	sum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64URLEncodeNoPad(sum[:])

	// generate state & nonce securely in production
	state, err = generateRandomString(32)
	if err != nil {
		return "", "", "", "", err
	}

	nonce, err = generateRandomString(32)
	if err != nil {
		return "", "", "", "", err
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", h.Config.ClientID)
	q.Set("redirect_uri", h.Config.RedirectURI)
	q.Set("scope", h.Config.Scopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")

	authURL = fmt.Sprintf("%s?%s", h.AuthEndpoint, q.Encode())
	return
}

// Login handler: build URL, store code_verifier/state/nonce in session, redirect
func (h *SingpassHandler) Login(c *gin.Context) {
	authURL, codeVerifier, state, nonce, err := h.BuildAuthURL(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	session := sessions.Default(c)
	session.Set("singpass_auth", map[string]string{
		"code_verifier": codeVerifier,
		"state":         state,
		"nonce":         nonce,
	})
	_ = session.Save()
	c.Redirect(http.StatusFound, authURL)
}

// createClientAssertion builds a signed JWT (client_assertion) using private_sig key (ES256)
func (h *SingpassHandler) createClientAssertion(ctx context.Context) (string, error) {
	now := time.Now()
	// claims
	iss := h.Config.ClientID
	sub := h.Config.ClientID
	aud := h.TokenEndpoint

	claims := map[string]interface{}{
		"iss": iss,
		"sub": sub,
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": fmt.Sprintf("%d", now.UnixNano()),
	}
	// signer
	sig := h.PrivateSig
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: sig}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", sig.KeyID))
	if err != nil {
		return "", err
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		return "", err
	}
	return compact, nil
}

// Callback handler: exchange code for tokens using client_assertion and code_verifier
func (h *SingpassHandler) Callback(c *gin.Context) {
	cookies := c.Request.Cookies()
	for _, ck := range cookies {
		fmt.Printf("cookie in callback: %s=%s\n", ck.Name, ck.Value)
	}

	session := sessions.Default(c)
	fmt.Printf("session: %v\n", session)
	raw := session.Get("singpass_auth")
	if raw == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no session"})
		return
	}
	authMap := raw.(map[string]string)
	expectedState := authMap["state"]
	if c.Query("state") != expectedState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state"})
		return
	}
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}
	codeVerifier := authMap["code_verifier"]

	// create client_assertion (signed JWT)
	clientAssertion, err := h.createClientAssertion(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create client assertion: " + err.Error()})
		return
	}

	// Token request form
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", h.Config.RedirectURI)
	form.Set("client_id", h.Config.ClientID)
	form.Set("code_verifier", codeVerifier)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", clientAssertion)

	req, _ := http.NewRequest("POST", h.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token request failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		c.JSON(resp.StatusCode, gin.H{"error": "token endpoint error", "body": string(body)})
		return
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid token response: " + err.Error()})
		return
	}

	// Validate ID Token
	ctx := context.Background()
	idToken, err := h.Verifier.Verify(ctx, tokenResp.IDToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid id_token: " + err.Error()})
		return
	}
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse id_token claims: " + err.Error()})
		return
	}

	// Fetch userinfo endpoint (if present)
	var userinfo interface{}
	if h.UserinfoEndpoint != "" && tokenResp.AccessToken != "" {
		req2, _ := http.NewRequest("GET", h.UserinfoEndpoint, nil)
		req2.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
		r2, err := client.Do(req2)
		if err == nil {
			defer r2.Body.Close()
			b2, _ := io.ReadAll(r2.Body)
			// If response looks like a JWT (compact), try to decrypt if encrypted JWE
			if r2.Header.Get("Content-Type") == "application/jwt" || bytes.Count(b2, []byte(".")) >= 4 {
				// try to decrypt JWE using private encryption JWK
				if h.PrivateEnc.Key != nil {
					obj, err := jose.ParseEncrypted(string(b2))
					if err == nil {
						decrypted, derr := obj.Decrypt(h.PrivateEnc.Key)
						if derr == nil {
							var u map[string]interface{}
							_ = json.Unmarshal(decrypted, &u)
							userinfo = u
						} else {
							userinfo = string(decrypted) // fallback
						}
					} else {
						userinfo = string(b2)
					}
				} else {
					userinfo = string(b2)
				}
			} else {
				_ = json.Unmarshal(b2, &userinfo)
			}
		}
	}

	// Save minimal session user data
	session.Set("user", map[string]interface{}{
		"claims":   claims,
		"userinfo": userinfo,
		"access":   tokenResp.AccessToken,
		"id_token": tokenResp.IDToken,
	})
	_ = session.Save()

	c.JSON(http.StatusOK, gin.H{
		"claims":   claims,
		"userinfo": userinfo,
	})
}

// JWKS endpoint serve your public jwks (so Singpass can fetch)
func (h *SingpassHandler) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, h.PublicJWKS)
}
