package context

import (
	"encoding/json"

	"github.com/COSSAS/gauth/models"
	"github.com/gin-gonic/gin"
)

const (
	userValueContextKey  = "user-context"
	userGroupsContextKey = "user-groups"
	TokenContextKey      = "token-context"
)

func SetContext(ginContext *gin.Context, user models.User) error {
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	ginContext.Set(userValueContextKey, string(userJSON))
	ginContext.Set(userGroupsContextKey, user.Groups)
	return nil
}

func SetTokenContext(ginContext *gin.Context, token string) error {
	ginContext.Set(TokenContextKey, token)
	return nil
}

func GetUserFromContext(ginContext *gin.Context) (models.User, bool) {
	userJSON, exists := ginContext.Get(userValueContextKey)
	if !exists {
		return models.User{}, false
	}
	userString, ok := userJSON.(string)
	if !ok {
		return models.User{}, false
	}
	var user models.User
	err := json.Unmarshal([]byte(userString), &user)
	if err != nil {
		return models.User{}, false
	}
	return user, true
}

func GetUserAssignedGroups(ginContext *gin.Context) []string {
	groups, exists := ginContext.Get(userGroupsContextKey)
	if !exists {
		return []string{}
	}
	assignedGroups, ok := groups.([]string)
	if !ok {
		return []string{}
	}
	return assignedGroups
}

func GetTokenFromContext(ginContext *gin.Context) (string, bool) {
	token, exists := ginContext.Get(TokenContextKey)
	if !exists {
		return "", false
	}
	tokenStr, ok := token.(string)
	if !ok {
		return "", false
	}
	return tokenStr, true
}
