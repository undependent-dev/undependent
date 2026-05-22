// Package auth provides user authentication: registration, login, JWT tokens, and password hashing.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Client handles authentication operations.
type Client struct {
	jwtSecret      string
	jwtExpiry      time.Duration
	passwordMinLen int
}

// New creates a new auth client.
func New() *Client {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = generateRandomSecret()
		os.Setenv("JWT_SECRET", secret)
	}

	return &Client{
		jwtSecret:      secret,
		jwtExpiry:      24 * time.Hour,
		passwordMinLen: 8,
	}
}

// HashPassword hashes a password using HMAC-SHA256 with a random salt.
// Returns a base64-encoded "salt:hash" string.
func HashPassword(password string) (string, error) {
	// Generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	// Derive key using HMAC-SHA256 with 1000 iterations for basic stretching
	hash := deriveKey(password, salt, 1000)

	// Encode as base64("salt:hash")
	encoded := base64.StdEncoding.EncodeToString([]byte(
		hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash),
	))

	return encoded, nil
}

// CheckPassword verifies a password against a hash.
func CheckPassword(password, hash string) error {
	decoded, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return fmt.Errorf("decode hash: %w", err)
	}

	parts := splitHexStr(string(decoded))
	if len(parts) != 2 {
		return fmt.Errorf("invalid hash format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}

	expectedHash, err := hex.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decode expected hash: %w", err)
	}

	computedHash := deriveKey(password, salt, 1000)

	if !hmac.Equal(expectedHash, computedHash) {
		return fmt.Errorf("password mismatch")
	}

	return nil
}

// deriveKey performs iterative HMAC-SHA256 key derivation.
func deriveKey(password string, salt []byte, iterations int) []byte {
	key := []byte(password)
	h := hmac.New(sha256.New, key)
	h.Write(salt)
	result := h.Sum(nil)

	for i := 1; i < iterations; i++ {
		h = hmac.New(sha256.New, key)
		h.Write(result)
		result = h.Sum(nil)
	}

	return result
}

// splitHexStr splits a "salt:hash" hex string.
func splitHexStr(s string) []string {
	idx := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			idx = i
			break
		}
	}
	if idx == -1 {
		return []string{s}
	}
	return []string{s[:idx], s[idx+1:]}
}

// GenerateJWT creates a JWT token for a user.
func (c *Client) GenerateJWT(userID, email string) (string, error) {
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"sub":   userID,
		"email": email,
		"iat":   now,
		"exp":   now + int64(c.jwtExpiry.Seconds()),
	}

	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := fmt.Sprintf("%s.%s", headerEncoded, claimsEncoded)

	mac := hmac.New(sha256.New, []byte(c.jwtSecret))
	mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)

	return fmt.Sprintf("%s.%s", signingInput, base64.RawURLEncoding.EncodeToString(signature)), nil
}

// ValidateJWT validates a JWT token and returns the user ID and email.
func (c *Client) ValidateJWT(tokenString string) (string, string, error) {
	parts := splitToken(tokenString)
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid token format")
	}

	signingInput := fmt.Sprintf("%s.%s", parts[0], parts[1])

	mac := hmac.New(sha256.New, []byte(c.jwtSecret))
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", fmt.Errorf("decode signature: %w", err)
	}

	if !hmac.Equal(expectedSig, actualSig) {
		return "", "", fmt.Errorf("invalid token signature")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("decode claims: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return "", "", fmt.Errorf("unmarshal claims: %w", err)
	}

	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return "", "", fmt.Errorf("token expired")
		}
	}

	userID, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)

	return userID, email, nil
}

// AuthMiddleware creates an HTTP middleware that validates JWT tokens.
func (c *Client) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "missing authorization header"})
			return
		}

		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid authorization header"})
			return
		}

		userID, email, err := c.ValidateJWT(authHeader[7:])
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid or expired token"})
			return
		}

		r.Header.Set("X-User-ID", userID)
		r.Header.Set("X-User-Email", email)

		next.ServeHTTP(w, r)
	})
}

// RegisterRequest represents a user registration request.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// LoginRequest represents a user login request.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// TokenResponse represents a JWT token response.
type TokenResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// User represents an authenticated user.
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// ValidateRegister validates a registration request.
func (c *Client) ValidateRegister(req RegisterRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	if len(req.Password) < c.passwordMinLen {
		return fmt.Errorf("password must be at least %d characters", c.passwordMinLen)
	}
	return nil
}

// ValidateLogin validates a login request.
func (c *Client) ValidateLogin(req LoginRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}

// splitToken splits a JWT into its three parts.
func splitToken(token string) []string {
	result := make([]string, 0, 3)
	start := 0
	for i := 0; i < 2; i++ {
		idx := -1
		for j := start; j < len(token); j++ {
			if token[j] == '.' {
				idx = j
				break
			}
		}
		if idx == -1 {
			break
		}
		result = append(result, token[start:idx])
		start = idx + 1
	}
	if start < len(token) {
		result = append(result, token[start:])
	}
	return result
}

func generateRandomSecret() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}