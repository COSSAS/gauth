package gauth

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"os"
	"strconv"
)

// Function returns crypto random string of specified string size; stringSize
func randString(stringSize int) (string, error) {
	byteArray := make([]byte, stringSize)
	if _, err := io.ReadFull(rand.Reader, byteArray); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(byteArray), nil
}

func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func GetEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	boolValue, err := strconv.ParseBool(value)
	if err != nil {
		log.Printf("Invalid boolean value for %s. Defaulting to %v. Error: %v", key, defaultValue, err)
		return defaultValue
	}
	return boolValue
}
