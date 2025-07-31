# Stage 1: Build the Go application
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are unchanged
RUN go mod download

# Copy the source code
COPY . .

# Build the Go application
# CGO_ENABLED=0 disables CGO, making the binary statically linked and suitable for Alpine
# -a ensures all packages are rebuilt
# -installsuffix cgo prevents issues with CGO-enabled builds
# -ldflags="-s -w" removes debug information and symbol tables, reducing binary size
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o user-service .

# Stage 2: Create the final lightweight image
FROM alpine:latest

# Install ca-certificates for HTTPS communication and create non-root user
RUN apk --no-cache add ca-certificates && \
    addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/user-service .

# Change ownership of the binary to the non-root user
RUN chown appuser:appgroup user-service && \
    chmod +x user-service

# Switch to non-root user
USER appuser

# Expose the port the application listens on
EXPOSE 8080

# Command to run the application
CMD ["./user-service"]