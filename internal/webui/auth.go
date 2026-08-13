package webui

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kilo666mj/oidcrp"
)

const sessionCookieName = "rilldns_session"

type OIDCConfig struct {
	Issuer          string
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	Scopes          []string
	AllowedSubjects []string
	AllowedEmails   []string
	AllowedGroups   []string
	SessionKey      string
	SessionMaxAge   time.Duration
}

type sessionClaims struct {
	Subject string `json:"sub"`
	Email   string `json:"email,omitempty"`
	Expires int64  `json:"exp"`
}

type authService struct {
	oidc   *oidcrp.Service
	aead   cipher.AEAD
	secure bool
	maxAge time.Duration
}

func newAuth(config OIDCConfig) (*authService, error) {
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(config.SessionKey))
	if err != nil || len(key) != 32 {
		return nil, errors.New("RILLDNS_SESSION_KEY must be 32 random bytes encoded with base64url without padding")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if config.SessionMaxAge <= 0 {
		config.SessionMaxAge = 12 * time.Hour
	}
	auth := &authService{aead: aead, secure: strings.HasPrefix(strings.ToLower(config.RedirectURL), "https://"), maxAge: config.SessionMaxAge}
	auth.oidc = oidcrp.New(oidcrp.Config{
		Issuer: config.Issuer, ClientID: config.ClientID, ClientSecret: config.ClientSecret,
		RedirectURL: config.RedirectURL, Scopes: config.Scopes,
		AllowedSubjects: config.AllowedSubjects, AllowedEmails: config.AllowedEmails, AllowedGroups: config.AllowedGroups,
		StateCookieName: "rilldns_oidc", LoginPath: "/login", SuccessPath: "/", APIPrefixes: []string{"/v1/"},
	}, auth)
	return auth, nil
}

func (a *authService) Valid(request *http.Request) bool {
	_, ok := a.identity(request)
	return ok
}

func (a *authService) Issue(writer http.ResponseWriter, _ *http.Request, identity oidcrp.Identity) error {
	claims := sessionClaims{Subject: identity.Subject, Email: identity.Email, Expires: time.Now().Add(a.maxAge).Unix()}
	plain, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	nonce := make([]byte, a.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := a.aead.Seal(nonce, nonce, plain, []byte(sessionCookieName))
	http.SetCookie(writer, &http.Cookie{
		Name: sessionCookieName, Value: base64.RawURLEncoding.EncodeToString(sealed), Path: "/",
		MaxAge: int(a.maxAge.Seconds()), HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (a *authService) Clear(writer http.ResponseWriter, _ *http.Request) {
	http.SetCookie(writer, &http.Cookie{Name: sessionCookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode})
}

func (a *authService) identity(request *http.Request) (sessionClaims, bool) {
	cookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		return sessionClaims{}, false
	}
	sealed, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(sealed) < a.aead.NonceSize() {
		return sessionClaims{}, false
	}
	nonce, ciphertext := sealed[:a.aead.NonceSize()], sealed[a.aead.NonceSize():]
	plain, err := a.aead.Open(nil, nonce, ciphertext, []byte(sessionCookieName))
	if err != nil {
		return sessionClaims{}, false
	}
	var claims sessionClaims
	if json.Unmarshal(plain, &claims) != nil || claims.Subject == "" || claims.Expires <= time.Now().Unix() {
		return sessionClaims{}, false
	}
	return claims, true
}

func (a *authService) actor(request *http.Request) string {
	claims, ok := a.identity(request)
	if !ok {
		return "oidc:unknown"
	}
	if claims.Email != "" {
		return "oidc:" + claims.Email
	}
	return "oidc:" + claims.Subject
}

func validateOIDC(config OIDCConfig) error {
	if strings.TrimSpace(config.Issuer) == "" || strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.RedirectURL) == "" {
		return fmt.Errorf("OIDC issuer, client ID, and redirect URL are required when the UI listener is enabled")
	}
	redirect, err := url.Parse(config.RedirectURL)
	if err != nil || redirect.Hostname() == "" {
		return fmt.Errorf("OIDC redirect URL must be an absolute URL")
	}
	if redirect.Scheme != "https" && !(redirect.Scheme == "http" && (redirect.Hostname() == "localhost" || redirect.Hostname() == "127.0.0.1" || redirect.Hostname() == "::1")) {
		return fmt.Errorf("OIDC redirect URL must use HTTPS (HTTP is allowed only for loopback development)")
	}
	if len(config.AllowedSubjects) == 0 && len(config.AllowedEmails) == 0 && len(config.AllowedGroups) == 0 {
		return fmt.Errorf("at least one OIDC subject, email, or group allowlist entry is required")
	}
	if len(config.AllowedEmails) != 0 {
		return fmt.Errorf("OIDC email allowlists are not supported because the provider's email_verified claim cannot be enforced; use subject or group allowlists")
	}
	return nil
}
