# user-service/docker/Dockerfile

# Stage 1: Build the Go application
FROM golang:1.24-alpine AS builder

# Set necessary environment variables for Go modules
ENV CGO_ENABLED=0 GOOS=linux

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum first to cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the application
# The output binary will be named 'user-service' and placed in /app/bin
RUN go build -o ./bin/user-service ./cmd/server/main.go

# Stage 2: Create the final lean image
FROM alpine:latest

# Install ca-certificates for HTTPS communication and create non-root user
RUN apk --no-cache add ca-certificates && \
    addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set the working directory
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/bin/user-service .

# Change ownership of the binary to the non-root user
RUN chown appuser:appgroup user-service && \
    chmod +x user-service

# Switch to non-root user
USER appuser

# Expose the port the application will listen on
# This port will be read from the APP_PORT environment variable in the Go app
EXPOSE 8080

# Command to run the executable
CMD ["./user-service"]
