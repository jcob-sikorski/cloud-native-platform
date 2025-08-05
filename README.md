Here's a comprehensive README for your project, created from the provided file structure and `docker-compose.yml`.

# User Service

This project is a microservice built with Go, responsible for managing users and authentication. It uses a PostgreSQL database, and all services are orchestrated using Docker Compose.

-----

## 🚀 Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:

  * **Docker:** Used to containerize the application and its dependencies.
  * **Docker Compose:** A tool for defining and running multi-container Docker applications.

### Setup

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/your-repo-name.git
    cd your-repo-name
    ```

2.  **Configure environment variables:**
    Create a file named `.env` in the root of the project. Copy the contents below and fill in the values. This file will be used by Docker Compose to configure the database and the application.

    ```bash
    # Database Configuration
    POSTGRES_DB=user_service
    DB_PORT=5432
    DB_HOST=postgres
    POSTGRES_USER=admin
    POSTGRES_PASSWORD=password
    DB_SSLMODE=disable

    # Application Configuration
    APP_PORT=8080
    JWT_SECRET=your_jwt_secret_key
    ```

    > ⚠️ **Note:** The `POSTGRES_PASSWORD` and `JWT_SECRET` are sensitive. For production, use a more secure password and secret key. The `hashadminpassword` service is provided to help you generate a secure hashed password for the initial admin user.

### Running the Application

To start all services (the PostgreSQL database and the user service), run the following command:

```bash
docker-compose up --build
```

The `--build` flag ensures that the Go service is built from its Dockerfile before starting. The application will be available at `http://localhost:8080`.

-----

## 📂 Project Structure

This project follows a standard Go project layout, with a few additions for Docker and database management.

  * **`db/`**: Contains the database initialization scripts.
      * `init.sql`: SQL script to set up tables and roles.
      * `init.sh`: A shell script that runs on container startup to ensure the database is ready.
  * **`docker-compose.yml`**: Defines the services, networks, and volumes for the multi-container application.
      * `postgres`: The PostgreSQL database service.
      * `user-service`: The Go microservice.
      * `test-runner`: A temporary service for running Go integration tests.
  * **`hashadminpassword/`**: A standalone Go utility to securely hash a password for an initial admin user. This can be used to generate a hashed password to insert into the database during setup.
  * **`user-service/`**: The core Go microservice directory.
      * `cmd/server/main.go`: The main entry point for the application.
      * `docker/Dockerfile`: Dockerfile for building the `user-service` image.
      * `internal/`: Contains all business logic and internal components.
          * `auth/`: JWT token handling and authentication middleware.
          * `config/`: Application configuration loading.
          * `database/`: Database connection and migration logic.
          * `handlers/`: HTTP request handlers for the API endpoints.
          * `models/`: Data structures for users and tokens.
          * `repositories/`: Database interaction logic using interfaces to allow for different database implementations.
          * `services/`: Business logic layer.
      * `pkg/`: Reusable packages and utilities.
      * `scripts/`: Utility scripts, such as database migration tools.
      * `test/`: Integration tests for the service.

-----

## 🐳 Docker Images

The `user-service` is built using a multistage Dockerfile to create a small, efficient, and secure production image. The build process compiles the Go application and then copies the binary into a minimal Alpine image.

### Building and Running Manually

If you prefer to build the image and run the container separately without Docker Compose:

**Build the image & run the container:**

```bash
docker-compose up --build
```

This command runs the application and maps port 8080 on your host machine to port 8080 inside the container.