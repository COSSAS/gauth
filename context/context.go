package context

import (
	"encoding/json"

	"github.com/COSSAS/gauth/models"
	"github.com/gin-gonic/gin"
)

const (
	userValueContextKey  = "user-context"
	userGroupsContextKey = "user-groups"
)

func SetContext(gc *gin.Context, user models.User) error {
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	gc.Set(userValueContextKey, string(userJSON))
	gc.Set(userGroupsContextKey, user.Groups)
	return nil
}

func GetUserFromContext(gc *gin.Context) (models.User, bool) {
	userJSON, exists := gc.Get(userValueContextKey)
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

func GetUserAssignedGroups(gc *gin.Context) []string {
	groups, exists := gc.Get(userGroupsContextKey)
	if !exists {
		return []string{}
	}
	assignedGroups, ok := groups.([]string)
	if !ok {
		return []string{}
	}
	return assignedGroups
}