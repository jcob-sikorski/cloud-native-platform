package repositories

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jcob-sikorski/cloud-native-platform/internal/models"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// PostgresUserRepository implements UserRepository for PostgreSQL
type PostgresUserRepository struct {
	db *sqlx.DB
}

// NewPostgresUserRepository creates a new instance of PostgresUserRepository
func NewPostgresUserRepository(db *sqlx.DB) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

// GetAllUsers retrieves all users from the database with pagination, filtering, and sorting
func (repo *PostgresUserRepository) GetAllUsers(limit, offset int, sortBy, sortOrder, roleFilter string) ([]models.UserResponse, error) {
	var users []models.User
	queryBuilder := `
        SELECT id, username, email, first_name, last_name,
               address_street, address_city, address_state, address_zip_code, address_country, roles, created_at, updated_at
        FROM users
    `
	args := []interface{}{}
	argCounter := 1

	// Add filtering by role
	if roleFilter != "" {
		queryBuilder += fmt.Sprintf(" WHERE $%d = ANY(roles)", argCounter)
		args = append(args, roleFilter)
		argCounter++
	}

	// Add sorting
	if sortBy != "" {
		if sortOrder == "desc" {
			queryBuilder += fmt.Sprintf(" ORDER BY %s DESC", sortBy)
		} else {
			queryBuilder += fmt.Sprintf(" ORDER BY %s ASC", sortBy)
		}
	} else {
		// Default sort order
		queryBuilder += " ORDER BY username ASC"
	}

	// Add pagination
	queryBuilder += fmt.Sprintf(" OFFSET $%d LIMIT $%d", argCounter, argCounter+1)
	args = append(args, offset, limit)

	err := repo.db.Select(&users, queryBuilder, args...)
	if err != nil {
		return nil, fmt.Errorf("error querying users: %w", err)
	}

	var userResponses []models.UserResponse
	for _, u := range users {
		userResponses = append(userResponses, convertToUserResponse(u))
	}
	return userResponses, nil
}

// GetUsersCount returns the total number of users, optionally filtered by role
func (repo *PostgresUserRepository) GetUsersCount(roleFilter string) (int, error) {
	var count int
	queryBuilder := "SELECT COUNT(*) FROM users"
	args := []interface{}{}
	if roleFilter != "" {
		queryBuilder += " WHERE $1 = ANY(roles)"
		args = append(args, roleFilter)
	}

	err := repo.db.Get(&count, queryBuilder, args...)
	if err != nil {
		return 0, fmt.Errorf("error counting users: %w", err)
	}
	return count, nil
}

// GetUserByID retrieves a user by their ID from the database
func (repo *PostgresUserRepository) GetUserByID(id string) (*models.UserResponse, error) {
	var u models.User
	err := repo.db.Get(&u, `
        SELECT id, username, email, password_hash, first_name, last_name,
               address_street, address_city, address_state, address_zip_code, address_country, roles, created_at, updated_at
        FROM users WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, nil // User not found
	}
	if err != nil {
		return nil, fmt.Errorf("error querying user by ID: %w", err)
	}

	userResp := convertToUserResponse(u)
	return &userResp, nil
}

// GetFullUserByID retrieves a full user by their ID from the database for internal use
func (repo *PostgresUserRepository) GetFullUserByID(id string) (*models.User, error) {
	var u models.User
	err := repo.db.Get(&u, `
        SELECT id, username, email, password_hash, first_name, last_name,
               address_street, address_city, address_state, address_zip_code, address_country, roles, created_at, updated_at
        FROM users WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, nil // User not found
	}
	if err != nil {
		return nil, fmt.Errorf("error querying full user by ID: %w", err)
	}
	return &u, nil
}

// GetUserByUsername retrieves a user by their username (used for login)
func (repo *PostgresUserRepository) GetUserByUsername(username string) (*models.User, error) {
	var u models.User
	err := repo.db.Get(&u, `
        SELECT id, username, email, password_hash, first_name, last_name,
               address_street, address_city, address_state, address_zip_code, address_country, roles, created_at, updated_at
        FROM users WHERE username = $1`, username)
	if err == sql.ErrNoRows {
		return nil, nil // User not found
	}
	if err != nil {
		return nil, fmt.Errorf("error querying user by username: %w", err)
	}
	return &u, nil
}

// CreateUser inserts a new user into the database
func (repo *PostgresUserRepository) CreateUser(user models.User) (*models.UserResponse, error) {
	if user.Username == "" || user.Email == "" {
		return nil, errors.New("username and email are required")
	}

	user.ID = uuid.New().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	var street, city, state, zipCode, country sql.NullString
	if user.Address != nil {
		street = sql.NullString{String: user.Address.Street, Valid: user.Address.Street != ""}
		city = sql.NullString{String: user.Address.City, Valid: user.Address.City != ""}
		state = sql.NullString{String: user.Address.State, Valid: user.Address.State != ""}
		zipCode = sql.NullString{String: user.Address.ZipCode, Valid: user.Address.ZipCode != ""}
		country = sql.NullString{String: user.Address.Country, Valid: user.Address.Country != ""}
	}

	_, err := repo.db.Exec(`
        INSERT INTO users (id, username, email, password_hash, first_name, last_name,
                          address_street, address_city, address_state, address_zip_code, address_country, roles, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		user.ID, user.Username, user.Email, user.PasswordHash,
		user.FirstName, user.LastName, street, city, state, zipCode, country, pq.Array(user.Roles), user.CreatedAt, user.UpdatedAt)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code.Name() == "unique_violation" {
			return nil, fmt.Errorf("user with this username or email already exists: %w", err)
		}
		return nil, fmt.Errorf("error creating user: %w", err)
	}

	userResp := convertToUserResponse(user)
	return &userResp, nil
}

// UpdateUser updates an existing user's details
func (repo *PostgresUserRepository) UpdateUser(id string, update models.UserUpdate) (*models.UserResponse, error) {
	var user models.User
	err := repo.db.Get(&user, "SELECT * FROM users WHERE id = $1", id)
	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("error retrieving user for update: %w", err)
	}

	// Build the update query dynamically
	updates := []string{}
	args := []interface{}{}
	argCounter := 1

	if update.Username != nil {
		updates = append(updates, fmt.Sprintf("username = $%d", argCounter))
		args = append(args, *update.Username)
		argCounter++
	}
	if update.Email != nil {
		updates = append(updates, fmt.Sprintf("email = $%d", argCounter))
		args = append(args, *update.Email)
		argCounter++
	}
	if update.FirstName != nil {
		updates = append(updates, fmt.Sprintf("first_name = $%d", argCounter))
		args = append(args, *update.FirstName)
		argCounter++
	}
	if update.LastName != nil {
		updates = append(updates, fmt.Sprintf("last_name = $%d", argCounter))
		args = append(args, *update.LastName)
		argCounter++
	}
	if update.Roles != nil {
		updates = append(updates, fmt.Sprintf("roles = $%d", argCounter))
		args = append(args, pq.Array(update.Roles))
		argCounter++
	}

	// Handle address fields
	if update.Address != nil {
		updates = append(updates, fmt.Sprintf("address_street = $%d", argCounter))
		args = append(args, sql.NullString{String: update.Address.Street, Valid: update.Address.Street != ""})
		argCounter++

		updates = append(updates, fmt.Sprintf("address_city = $%d", argCounter))
		args = append(args, sql.NullString{String: update.Address.City, Valid: update.Address.City != ""})
		argCounter++

		updates = append(updates, fmt.Sprintf("address_state = $%d", argCounter))
		args = append(args, sql.NullString{String: update.Address.State, Valid: update.Address.State != ""})
		argCounter++

		updates = append(updates, fmt.Sprintf("address_zip_code = $%d", argCounter))
		args = append(args, sql.NullString{String: update.Address.ZipCode, Valid: update.Address.ZipCode != ""})
		argCounter++

		updates = append(updates, fmt.Sprintf("address_country = $%d", argCounter))
		args = append(args, sql.NullString{String: update.Address.Country, Valid: update.Address.Country != ""})
		argCounter++
	}

	if len(updates) == 0 {
		return nil, errors.New("no fields to update")
	}

	// Add updated_at to the update query
	updates = append(updates, fmt.Sprintf("updated_at = $%d", argCounter))
	args = append(args, time.Now())
	argCounter++

	updateQuery := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d RETURNING *", strings.Join(updates, ", "), argCounter)
	args = append(args, id)

	var updatedUser models.User
	err = repo.db.Get(&updatedUser, updateQuery, args...)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code.Name() == "unique_violation" {
			return nil, fmt.Errorf("a user with this username or email already exists")
		}
		return nil, fmt.Errorf("error updating user: %w", err)
	}

	resp := convertToUserResponse(updatedUser)
	return &resp, nil
}

// DeleteUser removes a user from the database
func (repo *PostgresUserRepository) DeleteUser(id string) error {
	result, err := repo.db.Exec(`DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("error deleting user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error checking rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return errors.New("user not found")
	}
	return nil
}

// CheckUsernameExists checks for a duplicate username, excluding a specific user
func (repo *PostgresUserRepository) CheckUsernameExists(username string, excludeUserID string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM users WHERE username = $1"
	args := []interface{}{username}
	argCounter := 2

	if excludeUserID != "" {
		query += fmt.Sprintf(" AND id != $%d", argCounter)
		args = append(args, excludeUserID)
	}

	err := repo.db.Get(&count, query, args...)
	if err != nil {
		return false, fmt.Errorf("error checking username existence: %w", err)
	}
	return count > 0, nil
}

// CheckEmailExists checks for a duplicate email, excluding a specific user
func (repo *PostgresUserRepository) CheckEmailExists(email string, excludeUserID string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM users WHERE email = $1"
	args := []interface{}{email}
	argCounter := 2

	if excludeUserID != "" {
		query += fmt.Sprintf(" AND id != $%d", argCounter)
		args = append(args, excludeUserID)
	}

	err := repo.db.Get(&count, query, args...)
	if err != nil {
		return false, fmt.Errorf("error checking email existence: %w", err)
	}
	return count > 0, nil
}

// convertToUserResponse converts a User to UserResponse, omitting sensitive fields
func convertToUserResponse(user models.User) models.UserResponse {
	resp := models.UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Roles:     []string(user.Roles), // Convert pq.StringArray to []string
	}

	if user.AddressStreet.Valid || user.AddressCity.Valid || user.AddressState.Valid || user.AddressZipCode.Valid || user.AddressCountry.Valid {
		resp.Address = &models.Address{
			Street:  user.AddressStreet.String,
			City:    user.AddressCity.String,
			State:   user.AddressState.String,
			ZipCode: user.AddressZipCode.String,
			Country: user.AddressCountry.String,
		}
	}
	return resp
}
