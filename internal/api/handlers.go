package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// ── Request/Response Types ──

type CreateScanRequest struct {
	RepoURL string `json:"repo_url"`
	Email   string `json:"email"`
}

type CreateScanResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type ScanResponse struct {
	ID          string      `json:"id"`
	RepoURL     string      `json:"repo_url"`
	Status      string      `json:"status"`
	CreatedAt   string      `json:"created_at"`
	CompletedAt string      `json:"completed_at,omitempty"`
	Result      interface{} `json:"result,omitempty"`
	ReportURL   string      `json:"report_url,omitempty"`
}

type CreateReportRequest struct {
	ScanID string `json:"scan_id"`
	Email  string `json:"email"`
}

type CreateReportResponse struct {
	CheckoutURL string `json:"checkout_url"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// ── Handlers ──

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req CreateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RepoURL == "" || req.Email == "" {
		s.jsonError(w, http.StatusBadRequest, "repo_url and email are required")
		return
	}

	// Generate scan ID
	scanID := fmt.Sprintf("scan-%d", time.Now().UnixNano())

	// Create scan record
	if err := s.db.CreateScan(scanID, req.RepoURL, req.Email); err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to create scan")
		return
	}

	// Enqueue scan job
	payload := map[string]string{
		"scan_id":  scanID,
		"repo_url": req.RepoURL,
		"email":    req.Email,
	}
	if _, err := s.queue.Enqueue("scan_job", payload); err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to queue scan")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(CreateScanResponse{
		ID:     scanID,
		Status: "pending",
	})
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")

	scan, err := s.db.GetScan(scanID)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, "scan not found")
		return
	}

	resp := ScanResponse{
		ID:          scan.ID,
		RepoURL:     scan.RepoURL,
		Status:      scan.Status,
		CreatedAt:   scan.CreatedAt,
		CompletedAt: scan.CompletedAt,
		ReportURL:   scan.ReportURL,
	}

	if scan.ResultJSON != "" {
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(scan.ResultJSON), &result); err == nil {
			resp.Result = result
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleCreateReport(w http.ResponseWriter, r *http.Request) {
	var req CreateReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ScanID == "" || req.Email == "" {
		s.jsonError(w, http.StatusBadRequest, "scan_id and email are required")
		return
	}

	// Verify scan exists and is complete
	scan, err := s.db.GetScan(req.ScanID)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, "scan not found")
		return
	}

	if scan.Status != "complete" {
		s.jsonError(w, http.StatusBadRequest, "scan not yet complete")
		return
	}

	// Create Stripe checkout session
	checkoutURL, err := s.stripe.CreatePaymentLink(req.ScanID, req.Email)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to create payment link")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(CreateReportResponse{
		CheckoutURL: checkoutURL,
	})
}

func (s *Server) handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	scanID, err := s.stripe.HandleWebhook(r)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "webhook verification failed")
		return
	}

	if scanID == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Record payment in DB
	paymentID := fmt.Sprintf("pay-%d", time.Now().UnixNano())
	if err := s.db.CreatePayment(paymentID, scanID, "", 29900, "completed"); err != nil {
		fmt.Printf("warn: failed to record payment: %v\n", err)
		// Don't fail the webhook — payment recording is best-effort
	}

	// Get scan for email
	scan, scanErr := s.db.GetScan(scanID)
	if scanErr == nil && scan != nil && scan.Email != "" {
		if err := s.email.SendPaymentConfirmation(scan.Email, scanID, 29900); err != nil {
			fmt.Printf("warn: payment confirmation email failed: %v\n", err)
		}
	}

	// Enqueue report generation job
	payload := map[string]string{
		"scan_id": scanID,
		"email":   "",
	}
	if scanErr == nil && scan != nil && scan.Email != "" {
		payload["email"] = scan.Email
	}

	if _, err := s.queue.Enqueue("report_job", payload); err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to queue report")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ── Helpers ──

func (s *Server) jsonError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: msg})
}

// ── API Access Handlers ($0.50/scan) ──

func (s *Server) handleAPIScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RepoURL string `json:"repo_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RepoURL == "" {
		s.jsonError(w, http.StatusBadRequest, "repo_url required")
		return
	}

	scanID := fmt.Sprintf("api-%d", time.Now().UnixNano())

	if err := s.db.CreateScan(scanID, req.RepoURL, ""); err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to create scan")
		return
	}

	payload := map[string]string{
		"scan_id":  scanID,
		"repo_url": req.RepoURL,
		"email":    "",
		"tier":     "api",
	}
	if _, err := s.queue.Enqueue("scan_job", payload); err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to queue scan")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(CreateScanResponse{ID: scanID, Status: "pending"})
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		req.Name = "default"
	}

	key := s.apiKeys.CreateKey(req.Name)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"key":     key.Key,
		"name":    key.Name,
		"created": key.Created,
		"warning": "Store this key securely. It cannot be retrieved again.",
	})
}

// ── Team Dashboard Handlers ($199/mo) ──

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	scans, err := s.db.GetAllScans()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to fetch scans")
		return
	}

	result := make([]ScanResponse, 0, len(scans))
	for _, scan := range scans {
		resp := ScanResponse{
			ID:          scan.ID,
			RepoURL:     scan.RepoURL,
			Status:      scan.Status,
			CreatedAt:   scan.CreatedAt,
			CompletedAt: scan.CompletedAt,
			ReportURL:   scan.ReportURL,
		}
		if scan.ResultJSON != "" {
			var res map[string]interface{}
			if err := json.Unmarshal([]byte(scan.ResultJSON), &res); err == nil {
				resp.Result = res
			}
		}
		result = append(result, resp)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scans":  result,
		"total":  len(result),
		"tier":   "team",
	})
}

func (s *Server) handleDashboardScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	scan, err := s.db.GetScan(scanID)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, "scan not found")
		return
	}

	resp := ScanResponse{
		ID:          scan.ID,
		RepoURL:     scan.RepoURL,
		Status:      scan.Status,
		CreatedAt:   scan.CreatedAt,
		CompletedAt: scan.CompletedAt,
		ReportURL:   scan.ReportURL,
	}
	if scan.ResultJSON != "" {
		var res map[string]interface{}
		if err := json.Unmarshal([]byte(scan.ResultJSON), &res); err == nil {
			resp.Result = res
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
// ── Subscription Handlers ──

func (s *Server) handleCreateSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email   string `json:"email"`
		RepoURL string `json:"repo_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" {
		s.jsonError(w, http.StatusBadRequest, "email is required")
		return
	}

	url, err := s.stripe.CreateSubscriptionLink(req.Email, req.RepoURL)
	if err != nil {
		fmt.Printf("Stripe subscription error: %v\n", err)
		s.jsonError(w, http.StatusInternalServerError, "failed to create subscription")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"checkout_url": url,
		"tier":         "teams",
	})
}
