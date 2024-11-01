package gauth

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"

	"github.com/COSSAS/gauth/cookies"
	"github.com/COSSAS/gauth/utils"

	"github.com/COSSAS/gauth/api"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func (auth *Authenticator) OIDCRedirectToLogin(gc *gin.Context) {
	state, err := utils.RandString(16)
	if err != nil {
		api.JSONErrorStatus(gc, http.StatusInternalServerError, errors.New("failed to generate state"))
		return
	}
	nonce, err := utils.RandString(16)
	if err != nil {
		api.JSONErrorStatus(gc, http.StatusInternalServerError, errors.New("failed to generate nonce"))
	}
	nonceCookie, _ := cookies.NewCookie(cookies.Nonce, nonce)
	err = auth.Cookiejar.Store(gc, nonceCookie)
	if err != nil {
		api.JSONErrorStatus(gc, http.StatusInternalServerError, errors.New("failed to set nonce"))
		return
	}
	stateCookie, _ := cookies.NewCookie(cookies.State, state)
	err = auth.Cookiejar.Store(gc, stateCookie)
	if err != nil {
		api.JSONErrorStatus(gc, http.StatusInternalServerError, errors.New("failed to set state"))
		return
	}
	gc.Redirect(http.StatusFound, auth.OauthConfig.AuthCodeURL(state, oidc.Nonce(nonce)))
}

func (auth *Authenticator) OIDCCallBack(gc *gin.Context, redirectPath string) {
	stateCookie, isNew, err := auth.Cookiejar.Get(gc, cookies.State)

	if isNew || stateCookie == "" || err != nil {
		api.JSONErrorStatus(gc, http.StatusBadRequest, errors.New("state missing"))
		return
	}
	if stateCookie != gc.Query("state") {
		api.JSONErrorStatus(gc, http.StatusBadRequest, errors.New("state mismatch"))
		return
	}
	localContext := gc.Request.Context()
	if auth.skipTLSValidation {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		localContext = context.WithValue(localContext, oauth2.HTTPClient, client)
	}
	oauth2Token, err := auth.OauthConfig.Exchange(localContext, gc.Query("code"))
	if err != nil {
		api.JSONErrorStatus(gc, http.StatusUnauthorized, errors.New("could not exchange code for token"))
		return
	}
	rawIDtoken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		api.JSONErrorStatus(gc, http.StatusUnauthorized, errors.New("could not parse id_token"))
		return
	}
	verifier := auth.GetTokenVerifier()
	verifiedIDToken, err := verifier.Verify(localContext, rawIDtoken)
	if err != nil {
		api.JSONErrorStatus(gc, http.StatusUnauthorized, errors.New("failed to verify ID token"))
		return
	}
	nonce, isNewNonce, err := auth.Cookiejar.Get(gc, cookies.Nonce)
	if isNewNonce || nonce == "" || err != nil {
		api.JSONErrorStatus(gc, http.StatusBadRequest, errors.New("invalid or missing nonce"))
		return
	}
	if verifiedIDToken.Nonce != nonce {
		api.JSONErrorStatus(gc, http.StatusUnauthorized, errors.New("nonce for verified id token did not match"))
		return
	}
	_ = auth.Cookiejar.Delete(gc, cookies.Nonce)
	accessToken := oauth2Token.AccessToken

	userInfo, err := auth.GetProvider().UserInfo(localContext, oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		api.JSONErrorStatus(gc, http.StatusUnauthorized, errors.New("failed to get user info of access token"))
		return
	}

	if userInfo.Subject != verifiedIDToken.Subject {
		// authentik does not support at_hash so we can use the verifacess token.
		api.JSONErrorStatus(gc, http.StatusUnauthorized, errors.New("user info subject does not match ID token subject"))
		return
	}
	tokenCookie, err := cookies.NewCookie(cookies.Token, accessToken)
	if err != nil {
		api.JSONErrorStatus(gc, http.StatusInternalServerError, errors.New("failed to set access cookie token"))
		return
	}
	err = auth.Cookiejar.Store(gc, tokenCookie)
	if err != nil {
		api.JSONErrorStatus(gc, http.StatusInternalServerError, errors.New("internal error could not set access cookie"))
	}
	_ = auth.Cookiejar.Delete(gc, cookies.Nonce)
	_ = auth.Cookiejar.Delete(gc, cookies.State)
	gc.Redirect(http.StatusFound, redirectPath)
}

func (auth *Authenticator) Logout(gc *gin.Context, redirectPath string) {
	_ = auth.Cookiejar.Delete(gc, cookies.Token)

	var providerJSON map[string]interface{}
	if err := auth.GetProvider().Claims(&providerJSON); err != nil {
		gc.Redirect(http.StatusFound, redirectPath)
		return
	}

	endSessionEndpoint, ok := providerJSON["end_session_endpoint"].(string)
	if !ok {
		gc.Redirect(http.StatusFound, redirectPath)
		return
	}

	logoutURL, err := url.Parse(endSessionEndpoint)
	if err != nil {
		gc.Redirect(http.StatusFound, redirectPath)
		return
	}

	query := logoutURL.Query()
	query.Set("client_id", auth.OIDCconfig.ClientID)
	query.Set("post_logout_redirect_uri", redirectPath)

	logoutURL.RawQuery = query.Encode()

	gc.Redirect(http.StatusFound, logoutURL.String())
}
