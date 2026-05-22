// Package api provides authentication HTTP handlers.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/undep/undep/internal/auth"
)

// handleRegister handles user registration (POST /api/auth/register).
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req auth.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.auth.ValidateRegister(req); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Check if user already exists
	existing, err := s.db.GetUserByEmail(req.Email)
	if err == nil && existing != nil {
		s.jsonError(w, http.StatusConflict, "email already registered")
		return
	}

	// Hash password
	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	// Create user
	userID := fmt.Sprintf("user-%d", time.Now().UnixNano())
	if err := s.db.CreateUser(userID, req.Email, passwordHash, req.Name, "free"); err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Generate JWT token
	token, err := s.auth.GenerateJWT(userID, req.Email)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(auth.TokenResponse{
		Token: token,
		User: auth.User{
			ID:    userID,
			Email: req.Email,
			Name:  req.Name,
		},
	})
}

// handleLogin handles user login (POST /api/auth/login).
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req auth.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.auth.ValidateLogin(req); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Find user by email
	user, err := s.db.GetUserByEmail(req.Email)
	if err != nil {
		s.jsonError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	// Verify password
	if err := auth.CheckPassword(req.Password, user.PasswordHash); err != nil {
		s.jsonError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	// Generate JWT token
	token, err := s.auth.GenerateJWT(user.ID, user.Email)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(auth.TokenResponse{
		Token: token,
		User: auth.User{
			ID:    user.ID,
			Email: user.Email,
			Name:  user.Name,
		},
	})
}

// handleProfile returns the authenticated user's profile (GET /api/user/profile).
func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		s.jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	user, err := s.db.GetUserByID(userID)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, "user not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user": map[string]interface{}{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"tier":  user.Tier,
		},
	})
}