package config

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

// Config holds all application configuration.
type Config struct {
	Database  DatabaseConfig
	AppPort   string
	JWTSecret []byte
}

// DatabaseConfig holds database specific configuration.
type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() (*Config, error) {
	appPort := os.Getenv("APP_PORT")
	if appPort == "" {
		appPort = "8080" // Default port
		logrus.Warnf("APP_PORT not set, defaulting to %s", appPort)
	}

	jwtSecretStr := os.Getenv("JWT_SECRET")
	if jwtSecretStr == "" {
		return nil, fmt.Errorf("JWT_SECRET environment variable not set")
	}
	jwtSecret := []byte(jwtSecretStr)

	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		return nil, fmt.Errorf("DB_HOST environment variable not set")
	}
	dbPort := os.Getenv("DB_PORT")
	if dbPort == "" {
		return nil, fmt.Errorf("DB_PORT environment variable not set")
	}
	dbUser := os.Getenv("POSTGRES_USER") // Use POSTGRES_USER as defined in docker-compose.yml
	if dbUser == "" {
		return nil, fmt.Errorf("POSTGRES_USER environment variable not set")
	}
	dbPassword := os.Getenv("POSTGRES_PASSWORD") // Use POSTGRES_PASSWORD
	if dbPassword == "" {
		return nil, fmt.Errorf("POSTGRES_PASSWORD environment variable not set")
	}
	dbName := os.Getenv("POSTGRES_DB") // Use POSTGRES_DB
	if dbName == "" {
		return nil, fmt.Errorf("POSTGRES_DB environment variable not set")
	}
	dbSSLMode := os.Getenv("DB_SSLMODE")
	if dbSSLMode == "" {
		dbSSLMode = "disable" // Default to disable for local development
	}

	return &Config{
		AppPort:   appPort,
		JWTSecret: jwtSecret,
		Database: DatabaseConfig{
			Host:     dbHost,
			Port:     dbPort,
			User:     dbUser,
			Password: dbPassword,
			DBName:   dbName,
			SSLMode:  dbSSLMode,
		},
	}, nil
}
