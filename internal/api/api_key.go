// Package api provides API key authentication and rate limiting.
package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/undep/undep/internal/db"
)

// APIKeyManager handles API key creation, validation, and rate limiting.
// Keys are persisted to SQLite for durability across restarts.
type APIKeyManager struct {
	db      *db.DB
	mu      sync.RWMutex
	cache   map[string]*APIKeyEntry // in-memory cache for fast lookups
	rateMap map[string]*RateLimiter
}

// APIKeyEntry is the in-memory representation of a persisted API key.
type APIKeyEntry struct {
	Key      string    `json:"key"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	Active   bool      `json:"active"`
	Hash     string    `json:"-"` // stored hash for lookup
}

// RateLimiter implements a simple token bucket per API key.
type RateLimiter struct {
	tokens     int
	maxTokens  int
	refill     time.Duration
	lastRefill time.Time
	mu         sync.Mutex
}

// NewAPIKeyManager creates a new API key manager backed by the DB.
func NewAPIKeyManager(database *db.DB) *APIKeyManager {
	m := &APIKeyManager{
		db:      database,
		cache:   make(map[string]*APIKeyEntry),
		rateMap: make(map[string]*RateLimiter),
	}
	// Load existing keys from DB into cache
	if database != nil {
		keys, err := database.GetAllAPIKeys()
		if err == nil {
			for _, k := range keys {
				entry := &APIKeyEntry{
					Name:    k.Name,
					Created: k.CreatedAt,
					Active:  k.Active,
					Hash:    k.Hash,
				}
				m.cache[k.Hash] = entry
				m.rateMap[k.Hash] = &RateLimiter{
					tokens:     100,
					maxTokens:  100,
					refill:     time.Minute,
					lastRefill: time.Now(),
				}
			}
		}
	}
	return m
}

// CreateKey generates a new API key, persists it to DB, and caches it.
func (m *APIKeyManager) CreateKey(name string) *APIKeyEntry {
	raw := make([]byte, 32)
	rand.Read(raw)
	key := "undep_" + hex.EncodeToString(raw)
	h := sha256.Sum256([]byte(key))
	hash := hex.EncodeToString(h[:])

	id := fmt.Sprintf("key-%d", time.Now().UnixNano())

	entry := &APIKeyEntry{
		Key:     key,
		Name:    name,
		Created: time.Now(),
		Active:  true,
		Hash:    hash,
	}

	// Persist to DB
	if m.db != nil {
		if err := m.db.CreateAPIKey(id, name, hash); err != nil {
			fmt.Printf("warn: failed to persist API key: %v\n", err)
		}
	}

	m.mu.Lock()
	m.cache[hash] = entry
	m.rateMap[hash] = &RateLimiter{
		tokens:     100,
		maxTokens:  100,
		refill:     time.Minute,
		lastRefill: time.Now(),
	}
	m.mu.Unlock()

	return entry
}

// Validate checks if an API key is valid and within rate limits.
func (m *APIKeyManager) Validate(key string) bool {
	h := sha256.Sum256([]byte(key))
	hash := hex.EncodeToString(h[:])

	m.mu.RLock()
	entry, exists := m.cache[hash]
	m.mu.RUnlock()

	if !exists {
		// Try loading from DB (another instance may have created it)
		if m.db != nil {
			dbKey, err := m.db.GetAPIKeyByHash(hash)
			if err == nil && dbKey.Active {
				m.mu.Lock()
				m.cache[hash] = &APIKeyEntry{
					Name:    dbKey.Name,
					Created: dbKey.CreatedAt,
					Active:  true,
					Hash:    hash,
				}
				m.rateMap[hash] = &RateLimiter{
					tokens:     100,
					maxTokens:  100,
					refill:     time.Minute,
					lastRefill: time.Now(),
				}
				m.mu.Unlock()
				return m.rateLimit(hash)
			}
		}
		return false
	}

	if !entry.Active {
		return false
	}

	return m.rateLimit(hash)
}

// rateLimit checks and consumes a token from the rate limiter.
func (m *APIKeyManager) rateLimit(hash string) bool {
	m.mu.RLock()
	limiter := m.rateMap[hash]
	m.mu.RUnlock()

	if limiter == nil {
		return true
	}
	return limiter.Allow()
}

// Allow checks and consumes a token from the rate limiter.
func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if now.Sub(r.lastRefill) >= r.refill {
		r.tokens = r.maxTokens
		r.lastRefill = now
	}

	if r.tokens <= 0 {
		return false
	}
	r.tokens--
	return true
}

// AuthMiddleware returns an HTTP middleware that validates API keys.
func (m *APIKeyManager) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = r.URL.Query().Get("api_key")
		}

		if key == "" {
			http.Error(w, `{"error":"missing API key"}`, http.StatusUnauthorized)
			return
		}

		if !m.Validate(key) {
			h := sha256.Sum256([]byte(key))
			hash := hex.EncodeToString(h[:])
			m.mu.RLock()
			entry, exists := m.cache[hash]
			m.mu.RUnlock()
			if !exists || !entry.Active {
				http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
				return
			}
			http.Error(w, `{"error":"rate limit exceeded. 100 requests/minute"}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}