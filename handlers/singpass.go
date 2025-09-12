package handlers

import (
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

	"beast-tech-singpass-be/config"
	"beast-tech-singpass-be/helpers"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jws"
	jose "github.com/square/go-jose/v3"
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

	// Keys
	PublicJWS jose.JSONWebKey
}

// NewSingpassHandler creates and initializes discovery and verifiers
func NewSingpassHandler(cfg config.Config) (*SingpassHandler, error) {
	s := &SingpassHandler{Config: cfg}

	// Load private signing key
	sig, err := helpers.LoadJWKFromFile(cfg.Keys.PrivateSigPath)
	if err != nil {
		return nil, fmt.Errorf("load private signing key: %w", err)
	}
	s.PrivateSig = sig

	// Load private encryption key (optional)
	enc, err := helpers.LoadJWKFromFile(cfg.Keys.PrivateEncPath)
	if err == nil {
		s.PrivateEnc = enc
	}

	// Load public JWKS from local file
	pub, err := helpers.LoadJWKSetFromFile(cfg.Keys.PublicJwksPath)
	if err != nil {
		return nil, fmt.Errorf("load public jwks: %w", err)
	}
	s.PublicJWKS = pub

	// Pick the signing key from JWKS
	for _, k := range pub.Keys {
		if k.Use == "sig" {
			s.PublicJWS = k
			break
		}
	}
	if s.PublicJWS.Key == nil {
		return nil, fmt.Errorf("no signing key found in public JWKS")
	}

	// Discover provider & endpoints
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("issuer discovery: %w", err)
	}
	s.Provider = provider

	// Get endpoints from provider metadata
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

	// ID token verifier
	s.Verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

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
func (h *SingpassHandler) BuildAuthURL(c *gin.Context) (authURL string, state string, nonce string, err error) {
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return "", "", "", err
	}

	sum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64URLEncodeNoPad(sum[:])

	// generate state & nonce securely in production
	randomState, err := generateRandomString(16)
	if err != nil {
		return "", "", "", err
	}
	nonce, err = generateRandomString(32)
	if err != nil {
		return "", "", "", err
	}

	// 👇 embed both state and code_verifier into one base64 JSON
	stateData := map[string]string{
		"state":         randomState,
		"code_verifier": codeVerifier,
	}
	jsonBytes, _ := json.Marshal(stateData)
	state = base64.RawURLEncoding.EncodeToString(jsonBytes)

	// build auth URL
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
	return authURL, state, nonce, nil
}

// Login handler: build URL, store code_verifier/state/nonce in session, redirect
func (h *SingpassHandler) Login(c *gin.Context) {
	authURL, state, nonce, err := h.BuildAuthURL(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	session := sessions.Default(c)
	session.Set("singpass_auth", map[string]string{
		"state": state,
		"nonce": nonce,
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
	stateParam := c.Query("state")
	code := c.Query("code")
	if code == "" || stateParam == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code or state"})
		return
	}

	decoded, err := base64.RawURLEncoding.DecodeString(stateParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state encoding"})
		return
	}
	var stateData map[string]string
	if err := json.Unmarshal(decoded, &stateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state JSON"})
		return
	}

	codeVerifier := stateData["code_verifier"]
	if codeVerifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code_verifier in state"})
		return
	}

	clientAssertion, err := h.createClientAssertion(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create client assertion: " + err.Error()})
		return
	}

	// Token request
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

	// Verify ID token
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

	// Return tokens so frontend can decide when to call /userinfo
	c.JSON(http.StatusOK, gin.H{
		"claims":       claims,
		"access_token": tokenResp.AccessToken,
		"id_token":     tokenResp.IDToken,
	})
}

func (h *SingpassHandler) Userinfo(c *gin.Context) {
	accessToken := c.GetHeader("Authorization")
	if accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
		return
	}

	req, _ := http.NewRequest("GET", h.UserinfoEndpoint, nil)
	req.Header.Set("Authorization", accessToken)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "userinfo request failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		c.JSON(resp.StatusCode, gin.H{"error": "userinfo endpoint error", "body": string(body)})
		return
	}

	var userinfo interface{}
	if err := json.Unmarshal(body, &userinfo); err != nil {
		// fallback: raw string if not JSON
		userinfo = string(body)
	}

	c.JSON(http.StatusOK, userinfo)
}

// JWKS endpoint serve your public jwks (so Singpass can fetch)
func (h *SingpassHandler) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, h.PublicJWKS)
}

func (h *SingpassHandler) DecryptJWEHandler(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Parse incoming JWE
	jwe, err := jose.ParseEncrypted(req.Token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JWE", "detail": err.Error()})
		return
	}

	// Decrypt JWE using your private key
	decrypted, err := jwe.Decrypt(h.PrivateEnc.Key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt JWE", "detail": err.Error()})
		return
	}

	// The decrypted payload should be a compact JWS string
	jwsCompact := string(decrypted)

	// Verify the JWS using OIDC verifier
	if h.Verifier == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "verifier not configured"})
		return
	}

	idTok, err := h.Verifier.Verify(context.Background(), jwsCompact)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":  "invalid JWS (OIDC verify failed)",
			"detail": err.Error(),
		})
		return
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idTok.Claims(&claims); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse JWS claims", "detail": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"verified_by": "oidc.Verifier",
		"claims":      claims,
	})
}

func (h *SingpassHandler) UserinfoJWSHandler(c *gin.Context) {
	var body struct {
		Token string `json:"token"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}
	token := strings.TrimSpace(body.Token)
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "empty token"})
		return
	}

	// Step 1: Decrypt JWE with your private encryption key (h.PrivateEnc)
	decrypted, err := jwe.Decrypt([]byte(token), jwe.WithKey(jwa.ECDH_ES_A256KW, h.PrivateEnc.Key))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":  "failed to decrypt JWE",
			"detail": err.Error(),
		})
		return
	}

	// Step 2: Just output the decrypted payload (likely a JWS compact string)
	payloadStr := string(decrypted)

	// Try parsing JSON if it looks like JSON
	var claims map[string]interface{}
	if err := json.Unmarshal(decrypted, &claims); err != nil {
		// Not JSON? Just return raw string
		c.JSON(http.StatusOK, gin.H{
			"decrypted": payloadStr,
		})
		return
	}
}

func (h *SingpassHandler) VerifyInfoJWSHandler(c *gin.Context) {
	var body struct {
		Token string `json:"token"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}
	token := strings.TrimSpace(body.Token)
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "empty token"})
		return
	}

	// Parse JWS to get header and kid
	msg, err := jws.ParseString(token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JWS", "detail": err.Error()})
		return
	}
	kid := msg.Signatures()[0].ProtectedHeaders().KeyID()

	// Find matching key in JWKS
	var pubKey *jose.JSONWebKey
	for _, k := range h.PublicJWKS.Keys {
		if k.KeyID == kid {
			pubKey = &k
			break
		}
	}
	if pubKey == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no matching key for kid", "kid": kid})
		return
	}

	// Verify with the correct key
	payload, err := jws.Verify([]byte(token), jws.WithKey(jwa.ES256, pubKey.Key))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to verify JWS", "detail": err.Error()})
		return
	}

	// Parse claims
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid JSON payload", "detail": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"claims": claims})
}
