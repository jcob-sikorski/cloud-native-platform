-- Create the 'users' table if it doesn't exist
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    address_street VARCHAR(255),
    address_city VARCHAR(255),
    address_state VARCHAR(255),
    address_zip_code VARCHAR(20),
    address_country VARCHAR(255),
    roles TEXT[] -- PostgreSQL array type for roles
);

-- Optional: Add an index for faster lookups on email or username
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);

-- Optional: Add a default user for testing (only if the table is empty)
-- This is useful for initial setup but might be removed in production
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin') THEN
        INSERT INTO users (id, username, email, password_hash, first_name, last_name, roles)
        VALUES (
            'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', -- Example UUID
            'admin',
            'admin@example.com',
            '${ADMIN_PASSWORD_HASH}', -- This is the placeholder for your environment variable
            'Admin',
            'User',
            ARRAY['admin'] -- Example role
        );
    END IF;
END $$;