package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	password := "adminpassword" // The password you want to hash
	cost := bcrypt.DefaultCost  // Recommended cost for security

	// Generate the bcrypt hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		log.Fatalf("Error hashing password: %v", err)
	}

	fmt.Printf("Original Password: %s\n", password)
	fmt.Printf("Bcrypt Hash: %s\n", hashedPassword)

	// You can optionally verify the hash here
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		fmt.Println("Hash verification failed (this should not happen if generation was successful):", err)
	} else {
		fmt.Println("Hash verification successful!")
	}
}
