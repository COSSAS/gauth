package gauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/COSSAS/gauth/cookies"
	"github.com/COSSAS/gauth/models"
	"github.com/COSSAS/gauth/utils"
	"github.com/gin-gonic/gin"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

const (
	DEFAULT_OIDC_CALLBACK_PATH   = "/oidc-callback"
	COOKIE_ENCRYPTION_KEY_LENGTH = 32
	COOKIE_SECRET_KEY_LENGTH     = 32
)

type ConfigMode int

const (
	ModeVerify ConfigMode = iota
	ModeOIDCRedirect
)

type Provider string

const (
	Generic   Provider = "Generic"
	Authentik Provider = "Authentik"
)

type IAuth interface {
	Middleware(groups []string)
	LoadAuthContext() gin.HandlerFunc
	OIDCCallBack(gc *gin.Context, redirectPath string)
	OIDCRedirectToLogin(gc *gin.Context)
	Logout(gc *gin.Context)
}

type UserClaimsConfig struct {
	OIDCClaimUsernameField string
	OIDCClaimEmailField    string
	OIDCClaimNameField     string
	OIDCClaimGroupsField   string
}

type Authenticator struct {
	Cookiejar         cookies.ICookieJar
	OIDCconfig        *oidc.Config
	OauthConfig       *oauth2.Config
	verifierProvider  *oidc.Provider
	userclaimConfig   *UserClaimsConfig
	skipTLSValidation bool
}

type Config struct {
	Mode                ConfigMode
	ProviderLink        string
	ClientID            string
	ClientSecret        string
	SkipTLSValidation   bool
	OidcCallbackPath    string
	CookieJarSecret     string
	CookieEncryptionKey string
	RedirectURL         string
	Provider            Provider
}

func DefaultConfig() *Config {
	return &Config{
		Mode:         ModeVerify,
		ProviderLink: utils.GetEnv("OIDC_PROVIDER", ""),
		ClientID:     utils.GetEnv("OIDC_CLIENT_ID", ""),
		Provider:     Authentik,
	}
}

func OIDCRedirectConfig() *Config {
	return &Config{
		Mode:                ModeOIDCRedirect,
		ProviderLink:        utils.GetEnv("OIDC_PROVIDER", ""),
		ClientID:            utils.GetEnv("OIDC_CLIENT_ID", ""),
		ClientSecret:        utils.GetEnv("OIDC_CLIENT_SECRET", ""),
		SkipTLSValidation:   utils.GetEnvBool("OIDC_SKIP_TLS_VERIFY", false),
		OidcCallbackPath:    utils.GetEnv("OIDC_CALLBACK_PATH", DEFAULT_OIDC_CALLBACK_PATH),
		CookieJarSecret:     utils.GetEnv("COOKIE_SECRET_KEY", string(securecookie.GenerateRandomKey(COOKIE_SECRET_KEY_LENGTH))),
		CookieEncryptionKey: utils.GetEnv("COOKIE_ENCRYPTION_KEY", string(securecookie.GenerateRandomKey(COOKIE_ENCRYPTION_KEY_LENGTH))),
		RedirectURL:         redirectUrl(),
		Provider:            Authentik,
	}
}

func redirectUrl() string {
	domain := utils.GetEnv("SOARCA_GUI_DOMAIN", "http://localhost")
	port := utils.GetEnv("PORT", "8081")
	return fmt.Sprintf("%s:%s", domain, port)
}

func New(config *Config) (*Authenticator, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	client := setupHTTPClient(config.SkipTLSValidation)
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	provider, err := oidc.NewProvider(ctx, config.ProviderLink)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %v", err)
	}

	oidcConfig := &oidc.Config{ClientID: config.ClientID}
	oauthConfig := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	if config.Mode == ModeOIDCRedirect {
		oauthConfig.RedirectURL = fmt.Sprintf("%s%s", config.RedirectURL, config.OidcCallbackPath)
	}

	userClaimsConfig := &UserClaimsConfig{
		OIDCClaimUsernameField: "preferred_username",
		OIDCClaimEmailField:    "email",
		OIDCClaimNameField:     "name",
		OIDCClaimGroupsField:   "groups",
	}

	var cookieJar cookies.ICookieJar
	if config.Mode == ModeOIDCRedirect {
		cookieJar = cookies.NewCookieJar([]byte(config.CookieJarSecret), []byte(config.CookieEncryptionKey))
	}

	return &Authenticator{
		Cookiejar:         cookieJar,
		OIDCconfig:        oidcConfig,
		OauthConfig:       oauthConfig,
		verifierProvider:  provider,
		userclaimConfig:   userClaimsConfig,
		skipTLSValidation: config.SkipTLSValidation,
	}, nil
}

func validateConfig(config *Config) error {
	if config.ProviderLink == "" {
		return fmt.Errorf("invalid provider link")
	}
	if config.ClientID == "" {
		return fmt.Errorf("invalid OIDC client ID")
	}

	if config.Mode == ModeOIDCRedirect {
		if config.ClientSecret == "" {
			return fmt.Errorf("invalid OIDC client secret")
		}
		if config.OidcCallbackPath == "" {
			return fmt.Errorf("invalid OIDC callback path")
		}
		if !strings.HasPrefix(config.OidcCallbackPath, "/") {
			return fmt.Errorf("OIDC callback path must start with a forward slash (/)")
		}
		if config.RedirectURL == "" {
			return fmt.Errorf("invalid redirect URL")
		}
	}

	return nil
}

func setupHTTPClient(skipTLS bool) *http.Client {
	if skipTLS {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		log.Println("Warning: TLS verification is disabled. This should not be used in production.")
		return client
	}
	return http.DefaultClient
}

func (auth *Authenticator) GetProvider() *oidc.Provider {
	return auth.verifierProvider
}

func (auth *Authenticator) GetTokenVerifier() *oidc.IDTokenVerifier {
	return auth.verifierProvider.Verifier(auth.OIDCconfig)
}

func (auth *Authenticator) VerifyClaims(gc *gin.Context, token string) (*models.User, error) {
	verifier := auth.GetTokenVerifier()
	accessToken, err := verifier.Verify(gc, token)
	if err != nil {
		return nil, fmt.Errorf("could not obtain token from cookie: %s", err.Error())
	}
	var claims map[string]any
	if err := accessToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("could not map clains: %s", err.Error())
	}
	if _, ok := claims["iss"]; !ok {
		return nil, errors.New("no issues in claim")
	}
	return auth.mapClaimsToUser(claims)
}

func (auth *Authenticator) mapClaimsToUser(claims map[string]any) (*models.User, error) {
	user := &models.User{}

	if username, ok := claims[auth.userclaimConfig.OIDCClaimUsernameField].(string); ok {
		user.Username = username
	}
	if email, ok := claims[auth.userclaimConfig.OIDCClaimEmailField].(string); ok {
		user.Email = email
	}
	if name, ok := claims[auth.userclaimConfig.OIDCClaimNameField].(string); ok {
		user.Name = name
	}
	if groups, ok := claims[auth.userclaimConfig.OIDCClaimGroupsField].([]interface{}); ok {
		user.Groups = make([]string, len(groups))
		for i, g := range groups {
			user.Groups[i] = g.(string)
		}
	}

	return user, nil
}

func GetUserClaims(provider Provider) *UserClaimsConfig {
	switch provider {
	case Authentik:
		return getUserClaimsAuthentik()
	default:
		return getUserClaimsGeneric()
	}
}

func getUserClaimsAuthentik() *UserClaimsConfig {
	return &UserClaimsConfig{
		OIDCClaimUsernameField: "preferred_username",
		OIDCClaimEmailField:    "email",
		OIDCClaimNameField:     "name",
		OIDCClaimGroupsField:   "groups",
	}
}

func getUserClaimsGeneric() *UserClaimsConfig {
	return &UserClaimsConfig{
		OIDCClaimUsernameField: "sub",
		OIDCClaimEmailField:    "email",
		OIDCClaimNameField:     "name",
		OIDCClaimGroupsField:   "groups",
	}
}
