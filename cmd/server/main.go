// Package main is the entry point for the Undependent platform server.
package main

import (
	"fmt"
	"os"

	"github.com/undep/undep/internal/api"
	"github.com/undep/undep/internal/db"
	"github.com/undep/undep/internal/email"
	"github.com/undep/undep/internal/payment"
	"github.com/undep/undep/internal/queue"
	"github.com/undep/undep/internal/worker"
)

func main() {
	// Database
	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		dbPath = "data/undependent.db"
	}

	// Ensure data directory exists
	if err := os.MkdirAll("data", 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create data directory: %v\n", err)
		os.Exit(1)
	}

	database, err := db.New(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	// Email
	em := email.New()

	// Stripe
	st := payment.New()

	// Queue
	q := queue.New(database)

	// Worker
	w := worker.NewWorker(q, database, em)

	// Server
	srv := api.New(database, q, w, em, st)

	fmt.Println("Undependent Platform Server")
	fmt.Println("===========================")

	if err := srv.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}