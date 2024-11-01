package utils

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
)

// Function returns crypto random string of specified string size; stringSize
func RandString(stringSize int) (string, error) {
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
