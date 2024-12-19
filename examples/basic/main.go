package main

import (
	"log"

	"github.com/COSSAS/gauth"
	"github.com/gin-gonic/gin"
)

func main() {
	// Use the default OIDC configuration for Authentik with environment variables
	config := gauth.OIDCRedirectConfig()

	// Create authenticator
	auth, err := gauth.New(config)
	if err != nil {
		log.Fatalf("Failed to configure OIDC: %v", err)
	}

	router := gin.Default()

	// Configure routes based on authentication mode
	router.GET("/login", func(c *gin.Context) {
		// Redirect to OIDC login
		auth.OIDCRedirectToLogin(c)
	})

	router.GET("/oidc-callback", func(c *gin.Context) {
		// Handle OIDC callback
		auth.OIDCCallBack(c, "/dashboard")
	})

	// Logout handler
	router.GET("/logout", func(c *gin.Context) {
		auth.Logout(c, "/login")
	})

	// Protected routes
	protectedGroup := router.Group("/")
	protectedGroup.Use(auth.LoadAuthContext())
	protectedGroup.Use(auth.Middleware([]string{"admin"}))
	protectedGroup.GET("/dashboard", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Access to protected resource",
		})
	})

	err = router.Run(":8080")
	if err != nil {
		log.Fatal("Could not start server")
	}
}
