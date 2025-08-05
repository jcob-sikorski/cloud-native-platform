package models

import (
	"database/sql"
	"time"

	"github.com/lib/pq" // Required for pq.StringArray
)

// Address represents a user's address details
type Address struct {
	Street  string `json:"street" db:"address_street"`
	City    string `json:"city" db:"address_city"`
	State   string `json:"state" db:"address_state"`
	ZipCode string `json:"zipCode" db:"address_zip_code"`
	Country string `json:"country" db:"address_country"`
}

// User represents a user model for the e-commerce platform
type User struct {
	ID           string         `json:"id" db:"id"`
	Username     string         `json:"username" binding:"required" db:"username"`
	Email        string         `json:"email" binding:"required,email" db:"email"`
	PasswordHash string         `json:"passwordHash" binding:"required" db:"password_hash"`
	FirstName    string         `json:"firstName,omitempty" db:"first_name"`
	LastName     string         `json:"lastName,omitempty" db:"last_name"`
	Address      *Address       `json:"address,omitempty"`
	Roles        pq.StringArray `json:"roles,omitempty" db:"roles"`
	// Fields for Address struct, directly mapped for scanning with sqlx
	AddressStreet  sql.NullString `json:"-" db:"address_street"`
	AddressCity    sql.NullString `json:"-" db:"address_city"`
	AddressState   sql.NullString `json:"-" db:"address_state"`
	AddressZipCode sql.NullString `json:"-" db:"address_zip_code"`
	AddressCountry sql.NullString `json:"-" db:"address_country"`
	CreatedAt      time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at" db:"updated_at"`
}

// UserUpdate represents a user model for updating user details
type UserUpdate struct {
	Username        *string  `json:"username,omitempty"`
	Email           *string  `json:"email,omitempty"`
	FirstName       *string  `json:"firstName,omitempty"` // Added missing field
	LastName        *string  `json:"lastName,omitempty"`  // Added missing field
	Address         *Address `json:"address,omitempty"`   // Added missing field
	Roles           []string `json:"roles,omitempty"`
	CurrentPassword string   `json:"currentPassword,omitempty"` // For auth during password change
	NewPassword     string   `json:"newPassword,omitempty"`     // Plaintext new password
	PasswordHash    string   `json:"-"`                         // Internal use only
}

// UserResponse is a simplified struct for API responses, omitting sensitive fields
type UserResponse struct {
	ID        string   `json:"id"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	FirstName string   `json:"firstName,omitempty"`
	LastName  string   `json:"lastName,omitempty"`
	Address   *Address `json:"address,omitempty"`
	Roles     []string `json:"roles,omitempty"`
}
