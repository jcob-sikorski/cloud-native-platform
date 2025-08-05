package database

import (
	"fmt"
	"log"
	"time"

	"github.com/jcob-sikorski/cloud-native-platform/internal/config"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// ConnectDB attempts to connect to the database with retries
func ConnectDB(cfg config.DatabaseConfig) (*sqlx.DB, error) {
	dbURL := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)

	var db *sqlx.DB
	var err error
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		db, err = sqlx.Connect("postgres", dbURL)
		if err == nil {
			log.Println("Successfully connected to database")
			// Set connection pool settings
			db.SetMaxOpenConns(25)
			db.SetMaxIdleConns(25)
			db.SetConnMaxLifetime(5 * time.Minute)
			return db, nil
		}
		log.Printf("Failed to connect to database (attempt %d/%d): %v", i+1, maxRetries, err)
		time.Sleep(5 * time.Second) // Wait before retrying
	}
	return nil, fmt.Errorf("failed to connect to database after %d retries: %w", maxRetries, err)
}
