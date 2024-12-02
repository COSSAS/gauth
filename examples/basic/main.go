package main

import (
	"log"

	"github.com/COSSAS/gauth"
	"github.com/gin-gonic/gin"
)

func main() {
	// Use the default OIDC configuration with environment variables
	config := gauth.DefaultConfig()

	// Or use OIDC redirect configuration
	// config := gauth.OIDCRedirectConfig()

	// Create authenticator
	auth, err := gauth.New(config)
	if err != nil {
		log.Fatalf("Failed to configure OIDC: %v", err)
	}

	r := gin.Default()

	// Configure routes based on authentication mode
	r.GET("/login", func(c *gin.Context) {
		// Redirect to OIDC login
		auth.OIDCRedirectToLogin(c)
	})

	r.GET("/oidc-callback", func(c *gin.Context) {
		// Handle OIDC callback
		auth.OIDCCallBack(c, "/dashboard")
	})

	r.GET("/logout", func(c *gin.Context) {
		// Logout handler
		auth.Logout(c)
	})

	// Protected routes
	protectedGroup := r.Group("/")
	protectedGroup.Use(auth.LoadAuthContext())
	protectedGroup.Use(auth.Middleware([]string{"admin"}))
	protectedGroup.GET("/dashboard", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Access to protected resource",
		})
	})

	r.Run(":8080")
}
