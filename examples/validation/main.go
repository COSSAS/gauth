package main

import (
	"log"

	"github.com/COSSAS/gauth"
	"github.com/gin-gonic/gin"
)

func main() {
	// Create a new authenticator with default configuration
	authenticator, err := gauth.New(gauth.DefaultConfig())
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}

	r := gin.Default()

	// Load authentication context for all routes
	r.Use(authenticator.LoadAuthContext())

	// Public route (no authentication required)
	r.GET("/public", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "This is a public endpoint",
		})
	})

	// Protected route for all authenticated users
	r.GET("/profile", authenticator.Middleware([]string{}), func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome to your profile",
		})
	})

	// Admin-only route
	r.GET("/admin", authenticator.Middleware([]string{"admin"}), func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome, admin!",
		})
	})

	// Multiple group requirement
	r.GET("/management", authenticator.Middleware([]string{"managers", "executives"}), func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Management access granted",
		})
	})

	r.Run(":8080")
}
