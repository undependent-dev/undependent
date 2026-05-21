// Package api provides the HTTP server and routing.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/undep/undep/internal/db"
	"github.com/undep/undep/internal/email"
	"github.com/undep/undep/internal/payment"
	"github.com/undep/undep/internal/queue"
	"github.com/undep/undep/internal/report"
	"github.com/undep/undep/internal/worker"
)

// Server holds all dependencies for the HTTP server.
type Server struct {
	router    *chi.Mux
	db        *db.DB
	queue     *queue.Queue
	worker    *worker.Worker
	email     *email.Client
	stripe    *payment.Client
	apiKeys   *APIKeyManager
	httpSrv   *http.Server
}

// New creates a new Server with all dependencies wired up.
func New(db *db.DB, q *queue.Queue, w *worker.Worker, em *email.Client, st *payment.Client) *Server {
	s := &Server{
		db:      db,
		queue:   q,
		worker:  w,
		email:   em,
		stripe:  st,
		apiKeys: NewAPIKeyManager(db),
		router:  chi.NewRouter(),
	}

	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.RealIP)
	s.router.Use(middleware.Logger)
	s.router.Use(middleware.Recoverer)
	s.router.Use(middleware.Timeout(60 * time.Second))

	// CORS
	s.router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "Authorization"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Routes
	s.router.Get("/api/health", s.handleHealth)
	s.router.Post("/api/scan", s.handleCreateScan)
	s.router.Get("/api/scan/{id}", s.handleGetScan)
	s.router.Post("/api/report", s.handleCreateReport)
	s.router.Post("/api/webhook/stripe", s.handleStripeWebhook)
	s.router.Post("/api/subscription", s.handleCreateSubscription)

	// API access (authenticated, rate-limited)
	api := s.router.With(s.apiKeys.AuthMiddleware)
	api.Post("/api/v1/scan", s.handleAPIScan)
	api.Post("/api/v1/keys", s.handleCreateAPIKey)

	// Team dashboard (authenticated)
	dash := s.router.With(s.apiKeys.AuthMiddleware)
	dash.Get("/api/v1/dashboard", s.handleDashboard)
	dash.Get("/api/v1/dashboard/{id}", s.handleDashboardScan)

	// Serve marketing site
	s.router.Handle("/*", http.FileServer(http.Dir("docs/")))

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	s.httpSrv = &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: s.router,
	}

	return s
}

// Start begins the HTTP server and background workers.
func (s *Server) Start() error {
	// Start scan workers (4 goroutines)
	for i := 0; i < 4; i++ {
		go s.workerLoop("scan_job", s.worker.RunScanJob)
	}

	// Start report workers (2 goroutines)
	for i := 0; i < 2; i++ {
		go s.workerLoop("report_job", s.worker.RunReportJob)
	}

	// Start email workers (2 goroutines)
	for i := 0; i < 2; i++ {
		go s.workerLoop("send_email", s.worker.RunEmailJob)
	}

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Server starting on :%s\n", port)

	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.httpSrv.Shutdown(ctx)
}

// Run starts the server and blocks until interrupted.
func (s *Server) Run() error {
	go func() {
		if err := s.Start(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Server error: %v\n", err)
		}
	}()

	// Wait for interrupt
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\nShutting down...")
	return s.Shutdown()
}

// workerLoop polls the queue for jobs of a given type.
func (s *Server) workerLoop(jobType string, handler func(ctx context.Context, job *db.Job) error) {
	ctx := context.Background()
	for {
		job, err := s.queue.Dequeue(ctx, jobType)
		if err != nil || job == nil {
			if job == nil {
				time.Sleep(2 * time.Second)
			} else {
				fmt.Printf("Dequeue error for %s: %v\n", jobType, err)
				time.Sleep(5 * time.Second)
			}
			continue
		}

		fmt.Printf("Processing %s job: %s\n", jobType, job.ID)

		if err := handler(ctx, job); err != nil {
			fmt.Printf("Job %s failed: %v\n", job.ID, err)
			if err := s.queue.Failed(ctx, job, err.Error()); err != nil {
				fmt.Printf("Failed to mark job %s as failed: %v\n", job.ID, err)
			}
			continue
		}

		fmt.Printf("Job %s completed\n", job.ID)
	}
}

// ── Report generation helper ──

// GenerateReportPDF creates a PDF from a scan result.
func GenerateReportPDF(scan *db.Scan) ([]byte, error) {
	var result report.ScanResult
	if err := json.Unmarshal([]byte(scan.ResultJSON), &result); err != nil {
		return nil, fmt.Errorf("unmarshal scan result: %w", err)
	}
	return report.GeneratePDF(result)
}