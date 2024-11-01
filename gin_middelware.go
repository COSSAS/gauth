package gauth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/COSSAS/gauth/context"
	"github.com/COSSAS/gauth/cookies"

	"github.com/COSSAS/gauth/api"

	"github.com/gin-gonic/gin"
)

func (auth *Authenticator) Middleware(requiredGroups []string) gin.HandlerFunc {
	return func(ginContext *gin.Context) {
		_, exists := context.GetUserFromContext(ginContext)
		if !exists {
			api.JSONErrorStatus(ginContext, http.StatusUnauthorized, errors.New("user not authenticated"))
			ginContext.Abort()
			return
		}
		userGroups := context.GetUserAssignedGroups(ginContext)
		if !hasRequiredGroups(userGroups, requiredGroups) {
			api.JSONErrorStatus(ginContext, http.StatusForbidden, errors.New("insufficient permissions"))
			ginContext.Abort()
			return
		}
		ginContext.Next()
	}
}

func hasRequiredGroups(userGroups []string, requiredGroups []string) bool {
	if len(requiredGroups) == 0 {
		return true
	}
	groupSet := make(map[string]bool)
	for _, group := range userGroups {
		groupSet[group] = true
	}
	for _, group := range requiredGroups {
		if !groupSet[group] {
			return false
		}
	}
	return true
}

func (auth *Authenticator) LoadAuthContext() gin.HandlerFunc {
	return func(ginContext *gin.Context) {
		authToken := ginContext.Request.Header.Get("Authorization")

		switch {
		case authToken != "":
			auth.setBearerAuthContext()(ginContext)
		default:
			auth.setSessionAuthContext()(ginContext)
		}
		ginContext.Next()
	}
}

func (auth *Authenticator) setSessionAuthContext() gin.HandlerFunc {
	return func(ginContext *gin.Context) {
		tokenCookie, noCookie, err := auth.Cookiejar.Get(ginContext, cookies.Token)
		if noCookie {
			ginContext.Redirect(http.StatusFound, "/")
			ginContext.Abort()
			return
		}
		if err != nil {
			api.JSONErrorStatus(ginContext, http.StatusBadRequest, errors.New("could not get cookie"))
			ginContext.Abort()
			return
		}
		user, err := auth.VerifyClaims(ginContext, tokenCookie)
		if err != nil {
			api.JSONErrorStatus(ginContext, http.StatusUnauthorized, errors.New("could not map token claims"))
			ginContext.Abort()
			return
		}

		err = context.SetContext(ginContext, *user)
		if err != nil {
			api.JSONErrorStatus(ginContext, http.StatusInternalServerError, errors.New("could not set context"))
			ginContext.Abort()
			return
		}
		ginContext.Next()
	}
}

func (auth *Authenticator) setBearerAuthContext() gin.HandlerFunc {
	return func(ginContext *gin.Context) {
		authHeader := ginContext.Request.Header.Get("Authorization")
		if authHeader == "" {
			ginContext.Abort()
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		if tokenString == authHeader {
			api.JSONErrorStatus(ginContext, http.StatusUnauthorized, errors.New("invalid authorization header format"))
			ginContext.Abort()
			return
		}

		user, err := auth.VerifyClaims(ginContext, tokenString)
		if err != nil {
			api.JSONErrorStatus(ginContext, http.StatusUnauthorized, errors.New("invalid bearer token"))
			ginContext.Abort()
			return
		}

		err = context.SetContext(ginContext, *user)
		if err != nil {
			api.JSONErrorStatus(ginContext, http.StatusInternalServerError, errors.New("could not set context"))
			ginContext.Abort()
			return
		}

		ginContext.Next()
	}
}
