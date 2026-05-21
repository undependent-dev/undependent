// Package worker implements async job processors.
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/undep/undep/internal/db"
	"github.com/undep/undep/internal/license"
	"github.com/undep/undep/internal/osv"
	"github.com/undep/undep/internal/queue"
	"github.com/undep/undep/internal/report"
	"github.com/undep/undep/internal/spdx"
)

// ScanPayload is the input for a scan job.
type ScanPayload struct {
	ScanID  string `json:"scan_id"`
	RepoURL string `json:"repo_url"`
	Email   string `json:"email"`
	Tier    string `json:"tier"` // "free", "api", "paid" — defaults to "free"
}

// ScanResult is the output stored in the DB.
type ScanResult struct {
	RepoURL      string      `json:"repo_url"`
	Language     string      `json:"language"`
	DepCount     int         `json:"dep_count"`
	VulnCount    int         `json:"vuln_count"`
	RiskScore    int         `json:"risk_score"`
	RiskLevel    string      `json:"risk_level"`
	Dependencies []DepEntry  `json:"dependencies"`
	Vulns        []VulnEntry `json:"vulnerabilities"`
	Licenses     []LicEntry  `json:"licenses"`
	SPDX         string      `json:"spdx_json"`
}

type DepEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license"`
}

type VulnEntry struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Severity string `json:"severity"`
	Package  string `json:"package"`
}

type LicEntry struct {
	Module  string `json:"module"`
	Type    string `json:"type"`
	Viral   bool   `json:"viral"`
}

// Worker processes jobs from the queue.
type Worker struct {
	queue *queue.Queue
	db    *db.DB
	email EmailClient
}

// EmailClient is an interface for email delivery.
type EmailClient interface {
	SendFreeScanResult(to, scanID, depCount, vulnCount, riskScore, riskLevel string) error
	SendReportDelivered(to, scanID string, pdfBytes []byte) error
	SendPaymentConfirmation(to, scanID string, amount int) error
}

// NewWorker creates a new Worker.
func NewWorker(q *queue.Queue, db *db.DB, em EmailClient) *Worker {
	return &Worker{queue: q, db: db, email: em}
}

// RunScanJob processes a single scan job.
func (w *Worker) RunScanJob(ctx context.Context, job *db.Job) error {
	var payload ScanPayload
	if err := json.Unmarshal([]byte(job.Payload), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	// Clone repo to temp dir
	tmpDir, err := os.MkdirTemp("", "undep-scan-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := w.cloneRepo(ctx, tmpDir, payload.RepoURL); err != nil {
		return fmt.Errorf("clone repo: %w", err)
	}

	// Detect language
	lang := w.detectLanguage(filepath.Join(tmpDir, ""))

	// Parse dependencies
	deps := w.parseDependencies(ctx, filepath.Join(tmpDir, ""), lang)

	// Query OSV for vulnerabilities
	vulns := w.queryVulnerabilities(ctx, deps, lang)

	// Detect licenses
	licenses := w.detectLicenses(filepath.Join(tmpDir, ""), deps)

	// Generate SPDX BOM
	spdxJSON := w.generateSPDX(payload.RepoURL, deps, licenses)

	// Calculate risk score
	riskScore := w.calcRiskScore(vulns)
	riskLevel := w.riskLevel(riskScore)

	result := ScanResult{
		RepoURL:      payload.RepoURL,
		Language:     lang,
		DepCount:     len(deps),
		VulnCount:    len(vulns),
		RiskScore:    riskScore,
		RiskLevel:    riskLevel,
		Dependencies: deps,
		Vulns:        vulns,
		Licenses:     licenses,
		SPDX:         spdxJSON,
	}

	// Determine tier (default: "free")
	tier := payload.Tier
	if tier == "" {
		tier = "free"
	}

	// Tier-based result handling
	storeResult := result
	switch tier {
	case "api":
		// API tier: store full result, skip email entirely
		resultJSON, _ := json.Marshal(storeResult)
		if err := w.db.UpdateScanResult(payload.ScanID, string(resultJSON)); err != nil {
			return fmt.Errorf("store result: %w", err)
		}
		if err := w.queue.Complete(job.ID); err != nil {
			return fmt.Errorf("complete job: %w", err)
		}
		return nil

	case "free":
		// Free tier: truncate vulnerability details
		storeResult = w.truncateVulns(result)
		fallthrough

	default:
		// "paid" or unknown: store full result (free already truncated above)
		resultJSON, _ := json.Marshal(storeResult)
		if err := w.db.UpdateScanResult(payload.ScanID, string(resultJSON)); err != nil {
			return fmt.Errorf("store result: %w", err)
		}

		if err := w.queue.Complete(job.ID); err != nil {
			return fmt.Errorf("complete job: %w", err)
		}

		// Free tier: send summary email with CTA
		if tier == "free" && w.email != nil && payload.Email != "" {
			depCount := fmt.Sprintf("%d", result.DepCount)
			vulnCount := fmt.Sprintf("%d", result.VulnCount)
			riskScoreStr := fmt.Sprintf("%d", result.RiskScore)
			if err := w.email.SendFreeScanResult(payload.Email, payload.ScanID, depCount, vulnCount, riskScoreStr, result.RiskLevel); err != nil {
				fmt.Printf("warn: send free scan email failed: %v\n", err)
			}
		}
		// Paid tier: no email here — report_job handles PDF + email after payment
	}

	return nil
}

// truncateVulns replaces vulnerability details with redacted placeholders for free tier.
func (w *Worker) truncateVulns(result ScanResult) ScanResult {
	truncated := result
	if len(result.Vulns) > 0 {
		truncated.Vulns = make([]VulnEntry, len(result.Vulns))
		for i := range result.Vulns {
			truncated.Vulns[i] = VulnEntry{
				ID:       "REDACTED",
				Summary:  "Upgrade to full report for vulnerability details",
				Severity: "unknown",
				Package:  result.Vulns[i].Package,
			}
		}
	}
	return truncated
}

// RunReportJob generates a PDF report for a completed scan.
func (w *Worker) RunReportJob(ctx context.Context, job *db.Job) error {
	var payload struct {
		ScanID string `json:"scan_id"`
		Email  string `json:"email"`
	}
	if err := json.Unmarshal([]byte(job.Payload), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	scan, err := w.db.GetScan(payload.ScanID)
	if err != nil {
		return fmt.Errorf("get scan: %w", err)
	}

	var result ScanResult
	if err := json.Unmarshal([]byte(scan.ResultJSON), &result); err != nil {
		return fmt.Errorf("unmarshal scan result: %w", err)
	}

	// Generate PDF
	pdfBytes, err := w.generatePDF(result, scan.RepoURL)
	if err != nil {
		return fmt.Errorf("generate PDF: %w", err)
	}

	// Send report email directly
	emailAddr := payload.Email
	if emailAddr == "" && scan.Email != "" {
		emailAddr = scan.Email
	}
	if w.email != nil && emailAddr != "" {
		if err := w.email.SendReportDelivered(emailAddr, payload.ScanID, pdfBytes); err != nil {
			fmt.Printf("warn: send report email failed: %v\n", err)
		}
	}

	return w.queue.Complete(job.ID)
}

// RunEmailJob processes an email send job.
func (w *Worker) RunEmailJob(ctx context.Context, job *db.Job) error {
	var payload struct {
		ScanID    string `json:"scan_id"`
		Email     string `json:"email"`
		DepCount  string `json:"dep_count"`
		VulnCount string `json:"vuln_count"`
		RiskScore string `json:"risk_score"`
		RiskLevel string `json:"risk_level"`
	}
	if err := json.Unmarshal([]byte(job.Payload), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	if w.email != nil && payload.Email != "" {
		if err := w.email.SendFreeScanResult(payload.Email, payload.ScanID, payload.DepCount, payload.VulnCount, payload.RiskScore, payload.RiskLevel); err != nil {
			return fmt.Errorf("send email: %w", err)
		}
	}

	return w.queue.Complete(job.ID)
}

// ── Helpers ──

func (w *Worker) cloneRepo(ctx context.Context, dir, url string) error {
	// Strip trailing .git for cleaner paths
	url = strings.TrimSuffix(url, ".git")

	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", url, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git clone: %s: %w", string(out), err)
	}
	return nil
}

func (w *Worker) detectLanguage(repoDir string) string {
	checks := []struct {
		file     string
		language string
	}{
		{"go.mod", "go"},
		{"package.json", "javascript"},
		{"requirements.txt", "python"},
		{"Cargo.toml", "rust"},
	}
	for _, c := range checks {
		if _, err := os.Stat(filepath.Join(repoDir, c.file)); err == nil {
			return c.language
		}
	}
	return "unknown"
}

func (w *Worker) parseDependencies(ctx context.Context, repoDir, lang string) []DepEntry {
	var deps []DepEntry

	switch lang {
	case "go":
		deps = w.parseGoDeps(repoDir)
	case "javascript":
		deps = w.parseNodeDeps(repoDir)
	case "python":
		deps = w.parsePythonDeps(repoDir)
	case "rust":
		deps = w.parseRustDeps(repoDir)
	}

	return deps
}

func (w *Worker) parseGoDeps(repoDir string) []DepEntry {
	var deps []DepEntry
	goSumPath := filepath.Join(repoDir, "go.sum")
	data, err := os.ReadFile(goSumPath)
	if err != nil {
		return deps
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) >= 2 {
			modPath := parts[0]
			version := strings.TrimPrefix(parts[1], "v")
			deps = append(deps, DepEntry{Name: modPath, Version: version})
		}
	}
	return deps
}

func (w *Worker) parseNodeDeps(repoDir string) []DepEntry {
	var deps []DepEntry
	pkgPath := filepath.Join(repoDir, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return deps
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return deps
	}
	for name, ver := range pkg.Dependencies {
		deps = append(deps, DepEntry{Name: name, Version: strings.TrimPrefix(ver, "^")})
	}
	for name, ver := range pkg.DevDependencies {
		deps = append(deps, DepEntry{Name: name, Version: strings.TrimPrefix(ver, "^")})
	}
	return deps
}

func (w *Worker) parsePythonDeps(repoDir string) []DepEntry {
	var deps []DepEntry
	reqPath := filepath.Join(repoDir, "requirements.txt")
	data, err := os.ReadFile(reqPath)
	if err != nil {
		return deps
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ">=")
		if len(parts) == 2 {
			deps = append(deps, DepEntry{Name: strings.TrimSpace(parts[0]), Version: strings.TrimSpace(parts[1])})
		} else {
			deps = append(deps, DepEntry{Name: line, Version: "unknown"})
		}
	}
	return deps
}

func (w *Worker) parseRustDeps(repoDir string) []DepEntry {
	var deps []DepEntry
	cargoPath := filepath.Join(repoDir, "Cargo.toml")
	data, err := os.ReadFile(cargoPath)
	if err != nil {
		return deps
	}
	inDeps := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "[dependencies]" {
			inDeps = true
			continue
		}
		if strings.HasPrefix(line, "[") && inDeps {
			break
		}
		if inDeps && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			name := strings.TrimSpace(parts[0])
			version := strings.Trim(strings.TrimSpace(parts[1]), `"`+" ")
			deps = append(deps, DepEntry{Name: name, Version: version})
		}
	}
	return deps
}

func (w *Worker) queryVulnerabilities(ctx context.Context, deps []DepEntry, lang string) []VulnEntry {
	if len(deps) == 0 {
		return nil
	}

	ecosystem := osv.EcosystemForLang(lang)
	if ecosystem == "" {
		return nil
	}

	client := osv.NewClient()
	queries := make([]osv.BatchQuery, 0, len(deps))
	for _, d := range deps {
		if d.Version != "" && d.Version != "unknown" {
			queries = append(queries, osv.BatchQuery{
				Package:   d.Name,
				Version:   d.Version,
				Ecosystem: ecosystem,
			})
		}
	}

	if len(queries) == 0 {
		return nil
	}

	results, err := client.QueryBatch(ctx, queries)
	if err != nil {
		fmt.Printf("warn: OSV batch query failed: %v\n", err)
		return nil
	}

	var vulns []VulnEntry
	for _, r := range results {
		for _, v := range r.Vulns {
			vulns = append(vulns, VulnEntry{
				ID:       v.ID,
				Summary:  v.Summary,
				Severity: v.Severity,
				Package:  r.Package,
			})
		}
	}
	return vulns
}

func (w *Worker) detectLicenses(repoDir string, deps []DepEntry) []LicEntry {
	detector := license.NewDetector()
	var entries []LicEntry

	// Detect license for each dependency by looking in the vendor/cache dir
	// For web scans, we check the cloned repo's module cache
	for _, d := range deps {
		// Try to find the module source in Go module cache or repo subdirs
		modDir := filepath.Join(repoDir, "vendor", d.Name)
		if _, err := os.Stat(modDir); os.IsNotExist(err) {
			// For non-Go projects, check repo root
			info := detector.Detect(repoDir)
			entries = append(entries, LicEntry{
				Module: d.Name,
				Type:   info.Type,
				Viral:  info.Viral,
			})
			continue
		}
		info := detector.Detect(modDir)
		entries = append(entries, LicEntry{
			Module: d.Name,
			Type:   info.Type,
			Viral:  info.Viral,
		})
	}

	// Also detect the project's own license
	projectLic := license.DetectProjectLicense(repoDir)
	if projectLic != "" {
		// Add project license as first entry
		entries = append([]LicEntry{{Module: "project", Type: projectLic, Viral: false}}, entries...)
	}

	return entries
}

func (w *Worker) generateSPDX(projectName string, deps []DepEntry, licenses []LicEntry) string {
	// Build license lookup map
	licMap := make(map[string]string)
	for _, l := range licenses {
		licMap[l.Module] = l.Type
	}

	components := make([]spdx.Component, 0, len(deps))
	for _, d := range deps {
		lic := licMap[d.Name]
		if lic == "" {
			lic = "Unknown"
		}
		components = append(components, spdx.Component{
			Name:    d.Name,
			Version: d.Version,
			License: lic,
		})
	}

	return spdx.GenerateBOM(projectName, components)
}

func (w *Worker) calcRiskScore(vulns []VulnEntry) int {
	score := 0
	for _, v := range vulns {
		switch v.Severity {
		case "critical":
			score += 10
		case "high":
			score += 5
		case "medium":
			score += 2
		case "low":
			score += 1
		}
	}
	return score
}

func (w *Worker) riskLevel(score int) string {
	switch {
	case score >= 50:
		return "critical"
	case score >= 25:
		return "high"
	case score >= 10:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

func (w *Worker) generatePDF(result ScanResult, repoURL string) ([]byte, error) {
	// Convert to report.ScanResult
	reportResult := report.ScanResult{
		RepoURL:    result.RepoURL,
		Language:   result.Language,
		DepCount:   result.DepCount,
		VulnCount:  result.VulnCount,
		RiskScore:  result.RiskScore,
		RiskLevel:  result.RiskLevel,
		Dependencies: make([]report.DepEnt, len(result.Dependencies)),
		Vulns:        make([]report.VulnEnt, len(result.Vulns)),
		Licenses:     make([]report.LicEnt, len(result.Licenses)),
	}
	for i, d := range result.Dependencies {
		reportResult.Dependencies[i] = report.DepEnt{Name: d.Name, Version: d.Version, License: d.License}
	}
	for i, v := range result.Vulns {
		reportResult.Vulns[i] = report.VulnEnt{ID: v.ID, Summary: v.Summary, Severity: v.Severity, Package: v.Package}
	}
	for i, l := range result.Licenses {
		reportResult.Licenses[i] = report.LicEnt{Module: l.Module, Type: l.Type, Viral: l.Viral}
	}
	return report.GeneratePDF(reportResult)
}