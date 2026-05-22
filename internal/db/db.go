// Package db provides SQLite storage for scans, jobs, and payments.
package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
}

func New(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db := &DB{conn: conn}
	if err := db.Init(); err != nil {
		conn.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) Init() error {
	_, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS scans (
			id           TEXT PRIMARY KEY,
			repo_url     TEXT NOT NULL,
			email        TEXT,
			status       TEXT DEFAULT 'pending',
			created_at   TEXT DEFAULT (datetime('now')),
			completed_at TEXT,
			result_json  TEXT,
			report_url   TEXT
		);
		CREATE TABLE IF NOT EXISTS jobs (
			id         TEXT PRIMARY KEY,
			job_type   TEXT NOT NULL,
			payload    TEXT NOT NULL,
			status     TEXT DEFAULT 'pending',
			created_at TEXT DEFAULT (datetime('now')),
			attempts   INTEGER DEFAULT 0,
			error_msg  TEXT
		);
		CREATE TABLE IF NOT EXISTS payments (
			id                TEXT PRIMARY KEY,
			scan_id           TEXT REFERENCES scans(id),
			stripe_payment_id TEXT,
			amount            INTEGER,
			status            TEXT,
			created_at        TEXT DEFAULT (datetime('now'))
		);
		CREATE TABLE IF NOT EXISTS api_keys (
			id         TEXT PRIMARY KEY,
			name       TEXT NOT NULL,
			hash       TEXT NOT NULL UNIQUE,
			active     INTEGER DEFAULT 1,
			created_at TEXT DEFAULT (datetime('now'))
		);
		CREATE TABLE IF NOT EXISTS users (
			id           TEXT PRIMARY KEY,
			email        TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			name         TEXT,
			tier         TEXT DEFAULT 'free',
			created_at   TEXT DEFAULT (datetime('now'))
		);
		CREATE TABLE IF NOT EXISTS subscriptions (
			id              TEXT PRIMARY KEY,
			user_id         TEXT REFERENCES users(id),
			stripe_sub_id   TEXT,
			tier            TEXT NOT NULL,
			status          TEXT DEFAULT 'active',
			created_at      TEXT DEFAULT (datetime('now')),
			cancel_at       TEXT
		);
		CREATE TABLE IF NOT EXISTS github_installs (
			id              INTEGER PRIMARY KEY,
			owner           TEXT NOT NULL,
			repo            TEXT,
			installation_id TEXT NOT NULL UNIQUE,
			status          TEXT DEFAULT 'active',
			created_at      TEXT DEFAULT (datetime('now'))
		);
		CREATE INDEX IF NOT EXISTS idx_jobs_type ON jobs(job_type, status, created_at);
		CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, created_at);
		CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
		CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
		CREATE INDEX IF NOT EXISTS idx_subs_user ON subscriptions(user_id);
	`)
	return err
}

func (db *DB) Close() error {
	return db.conn.Close()
}

// ── Scans ──

type Scan struct {
	ID          string `json:"id"`
	RepoURL     string `json:"repo_url"`
	Email       string `json:"email,omitempty"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	CompletedAt string `json:"completed_at,omitempty"`
	ResultJSON  string `json:"result_json,omitempty"`
	ReportURL   string `json:"report_url,omitempty"`
}

func (db *DB) CreateScan(id, repoURL, email string) error {
	_, err := db.conn.Exec(
		"INSERT INTO scans (id, repo_url, email) VALUES (?, ?, ?)", id, repoURL, email,
	)
	return err
}

func (db *DB) GetScan(id string) (*Scan, error) {
	s := &Scan{}
	err := db.conn.QueryRow(`
		SELECT id, repo_url, email, status, created_at, completed_at, result_json, report_url
		FROM scans WHERE id = ?`, id,
	).Scan(&s.ID, &s.RepoURL, &s.Email, &s.Status, &s.CreatedAt, &s.CompletedAt, &s.ResultJSON, &s.ReportURL)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("scan not found: %s", id)
	}
	return s, err
}

func (db *DB) UpdateScanStatus(id, status string) error {
	_, err := db.conn.Exec("UPDATE scans SET status = ? WHERE id = ?", status, id)
	return err
}

func (db *DB) UpdateScanResult(id, resultJSON string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.conn.Exec(
		"UPDATE scans SET status = 'complete', completed_at = ?, result_json = ? WHERE id = ?",
		now, resultJSON, id,
	)
	return err
}

func (db *DB) UpdateScanReportURL(id, url string) error {
	_, err := db.conn.Exec("UPDATE scans SET report_url = ? WHERE id = ?", url, id)
	return err
}

// ── Jobs ──

type Job struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Payload   string `json:"payload"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	Attempts  int    `json:"attempts"`
	ErrMsg    string `json:"error_msg,omitempty"`
}

func (db *DB) CreateJob(id, jobType, payload string) error {
	_, err := db.conn.Exec(
		"INSERT INTO jobs (id, job_type, payload) VALUES (?, ?, ?)", id, jobType, payload,
	)
	return err
}

func (db *DB) DequeueJob(jobType string) (*Job, error) {
	// Pick oldest pending job of this type, mark as running atomically
	j := &Job{}
	err := db.conn.QueryRow(`
		UPDATE jobs SET status = 'running', attempts = attempts + 1
		WHERE id = (
			SELECT id FROM jobs WHERE job_type = ? AND status = 'pending'
			ORDER BY created_at ASC LIMIT 1
		) RETURNING id, job_type, payload, status, created_at, attempts, error_msg`,
		jobType,
	).Scan(&j.ID, &j.Type, &j.Payload, &j.Status, &j.CreatedAt, &j.Attempts, &j.ErrMsg)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no pending jobs")
	}
	return j, err
}

func (db *DB) MarkJobComplete(id string) error {
	_, err := db.conn.Exec("UPDATE jobs SET status = 'complete' WHERE id = ?", id)
	return err
}

func (db *DB) MarkJobFailed(id, errMsg string) error {
	_, err := db.conn.Exec("UPDATE jobs SET status = ?, error_msg = ? WHERE id = ?", "failed", errMsg, id)
	return err
}

func (db *DB) RequeueJob(id string) error {
	_, err := db.conn.Exec("UPDATE jobs SET status = 'pending' WHERE id = ?", id)
	return err
}

// ── Payments ──

type Payment struct {
	ID              string `json:"id"`
	ScanID          string `json:"scan_id"`
	StripePaymentID string `json:"stripe_payment_id,omitempty"`
	Amount          int    `json:"amount"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
}

func (db *DB) CreatePayment(id, scanID, stripeID string, amount int, status string) error {
	_, err := db.conn.Exec(
		"INSERT INTO payments (id, scan_id, stripe_payment_id, amount, status) VALUES (?, ?, ?, ?, ?)",
		id, scanID, stripeID, amount, status,
	)
	return err
}

func (db *DB) GetPayment(id string) (*Payment, error) {
	p := &Payment{}
	err := db.conn.QueryRow(`
		SELECT id, scan_id, stripe_payment_id, amount, status, created_at
		FROM payments WHERE id = ?`, id,
	).Scan(&p.ID, &p.ScanID, &p.StripePaymentID, &p.Amount, &p.Status, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("payment not found")
	}
	return p, err
}

func (db *DB) UpdatePaymentStatus(id, status string) error {
	_, err := db.conn.Exec("UPDATE payments SET status = ? WHERE id = ?", status, id)
	return err
}

func (db *DB) GetAllScans() ([]*Scan, error) {
	rows, err := db.conn.Query(`
		SELECT id, repo_url, email, status, created_at, completed_at, result_json, report_url
		FROM scans ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*Scan
	for rows.Next() {
		s := &Scan{}
		if err := rows.Scan(&s.ID, &s.RepoURL, &s.Email, &s.Status, &s.CreatedAt, &s.CompletedAt, &s.ResultJSON, &s.ReportURL); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}

// ── API Keys ──

type APIKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Hash      string    `json:"-"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

func (db *DB) CreateAPIKey(id, name, hash string) error {
	_, err := db.conn.Exec(
		"INSERT INTO api_keys (id, name, hash) VALUES (?, ?, ?)", id, name, hash,
	)
	return err
}

func (db *DB) GetAPIKeyByHash(hash string) (*APIKey, error) {
	k := &APIKey{}
	err := db.conn.QueryRow(`
		SELECT id, name, hash, active, created_at FROM api_keys WHERE hash = ?`, hash,
	).Scan(&k.ID, &k.Name, &k.Hash, &k.Active, &k.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("api key not found")
	}
	return k, err
}

func (db *DB) GetAllAPIKeys() ([]*APIKey, error) {
	rows, err := db.conn.Query(`
		SELECT id, name, hash, active, created_at FROM api_keys ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*APIKey
	for rows.Next() {
		k := &APIKey{}
		var active int
		var createdAt string
		if err := rows.Scan(&k.ID, &k.Name, &k.Hash, &active, &createdAt); err != nil {
			return nil, err
		}
		k.Active = active == 1
		k.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// ── Users ──

type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	Name         string `json:"name,omitempty"`
	Tier         string `json:"tier"`
	CreatedAt    string `json:"created_at"`
}

func (db *DB) CreateUser(id, email, passwordHash, name, tier string) error {
	_, err := db.conn.Exec(
		"INSERT INTO users (id, email, password_hash, name, tier) VALUES (?, ?, ?, ?, ?)",
		id, email, passwordHash, name, tier,
	)
	return err
}

func (db *DB) GetUserByEmail(email string) (*User, error) {
	u := &User{}
	err := db.conn.QueryRow(`
		SELECT id, email, password_hash, name, tier, created_at FROM users WHERE email = ?`, email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Tier, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	return u, err
}

func (db *DB) GetUserByID(id string) (*User, error) {
	u := &User{}
	err := db.conn.QueryRow(`
		SELECT id, email, password_hash, name, tier, created_at FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Tier, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	return u, err
}

func (db *DB) UpdateUserTier(id, tier string) error {
	_, err := db.conn.Exec("UPDATE users SET tier = ? WHERE id = ?", tier, id)
	return err
}

// ── Subscriptions ──

type Subscription struct {
	ID          string `json:"id"`
	UserID      string `json:"user_id"`
	StripeSubID string `json:"stripe_sub_id,omitempty"`
	Tier        string `json:"tier"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	CancelAt    string `json:"cancel_at,omitempty"`
}

func (db *DB) CreateSubscription(id, userID, stripeSubID, tier, status string) error {
	_, err := db.conn.Exec(
		"INSERT INTO subscriptions (id, user_id, stripe_sub_id, tier, status) VALUES (?, ?, ?, ?, ?)",
		id, userID, stripeSubID, tier, status,
	)
	return err
}

func (db *DB) GetSubscriptionByStripeID(stripeSubID string) (*Subscription, error) {
	s := &Subscription{}
	err := db.conn.QueryRow(`
		SELECT id, user_id, stripe_sub_id, tier, status, created_at, cancel_at
		FROM subscriptions WHERE stripe_sub_id = ?`, stripeSubID,
	).Scan(&s.ID, &s.UserID, &s.StripeSubID, &s.Tier, &s.Status, &s.CreatedAt, &s.CancelAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("subscription not found")
	}
	return s, err
}

func (db *DB) GetSubscriptionByUserID(userID string) (*Subscription, error) {
	s := &Subscription{}
	err := db.conn.QueryRow(`
		SELECT id, user_id, stripe_sub_id, tier, status, created_at, cancel_at
		FROM subscriptions WHERE user_id = ? AND status = 'active'`, userID,
	).Scan(&s.ID, &s.UserID, &s.StripeSubID, &s.Tier, &s.Status, &s.CreatedAt, &s.CancelAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("subscription not found")
	}
	return s, err
}

func (db *DB) UpdateSubscriptionStatus(id, status string) error {
	_, err := db.conn.Exec("UPDATE subscriptions SET status = ? WHERE id = ?", status, id)
	return err
}

// ── GitHub Installs ──

type GitHubInstall struct {
	ID            int    `json:"id"`
	Owner         string `json:"owner"`
	Repo          string `json:"repo,omitempty"`
	InstallationID string `json:"installation_id"`
	Status        string `json:"status"`
	CreatedAt     string `json:"created_at"`
}

func (db *DB) CreateGitHubInstall(installationID, owner, repo, status string) error {
	_, err := db.conn.Exec(
		"INSERT INTO github_installs (installation_id, owner, repo, status) VALUES (?, ?, ?, ?)",
		installationID, owner, repo, status,
	)
	return err
}

func (db *DB) GetGitHubInstallByInstallationID(installationID string) (*GitHubInstall, error) {
	g := &GitHubInstall{}
	err := db.conn.QueryRow(`
		SELECT id, owner, repo, installation_id, status, created_at
		FROM github_installs WHERE installation_id = ?`, installationID,
	).Scan(&g.ID, &g.Owner, &g.Repo, &g.InstallationID, &g.Status, &g.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("github install not found")
	}
	return g, err
}

func (db *DB) UpdateGitHubInstallStatus(installationID, status string) error {
	_, err := db.conn.Exec("UPDATE github_installs SET status = ? WHERE installation_id = ?", status, installationID)
	return err
}