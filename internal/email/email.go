// Package email handles outbound email delivery via Resend API.
package email

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// Client wraps the Resend API.
type Client struct {
	apiKey    string
	fromEmail string
	http      *http.Client
}

// New creates a new email client.
func New() *Client {
	apiKey := os.Getenv("RESEND_API_KEY")
	from := os.Getenv("FROM_EMAIL")
	if from == "" {
		from = "Undependent <noreply@undependent.dev>"
	}
	return &Client{
		apiKey:    apiKey,
		fromEmail: from,
		http:      &http.Client{},
	}
}

// SendFreeScanResult sends free scan results with CTA for paid report.
func (c *Client) SendFreeScanResult(to string, scanID, depCount, vulnCount, riskScore, riskLevel string) error {
	subject := fmt.Sprintf("Your Undependent Scan Results — %s Risk", riskLevel)
	html := fmt.Sprintf(freeScanTemplate,
		depCount, vulnCount, riskScore, riskLevel,
		safeColor(riskLevel),
		fmt.Sprintf("https://undependent.dev/api/report?scan_id=%s&email=%s", scanID, to),
	)
	return c.send(to, subject, html)
}

// SendReportDelivered sends the full PDF report.
func (c *Client) SendReportDelivered(to, scanID string, pdfBytes []byte) error {
	subject := "Your Undependent Full Security Report"
	html := fmt.Sprintf(reportTemplate,
		scanID,
		"https://undependent.dev/pricing",
	)

	payload := resendRequest{
		From:    c.fromEmail,
		To:      []string{to},
		Subject: subject,
		HTML:    html,
		Attachments: []resendAttachment{
			{
				Filename:    fmt.Sprintf("undependent-report-%s.pdf", scanID),
				Content:     base64.StdEncoding.EncodeToString(pdfBytes),
			},
		},
	}
	return c.sendJSON(payload)
}

// SendPaymentConfirmation sends a payment receipt.
func (c *Client) SendPaymentConfirmation(to, scanID string, amount int) error {
	subject := "Payment Confirmation — Undependent"
	html := fmt.Sprintf(paymentTemplate,
		fmt.Sprintf("$%d", amount/100),
		scanID,
	)
	return c.send(to, subject, html)
}

// ── Internal ──

func (c *Client) send(to, subject, html string) error {
	payload := resendRequest{
		From:    c.fromEmail,
		To:      []string{to},
		Subject: subject,
		HTML:    html,
	}
	return c.sendJSON(payload)
}

func (c *Client) sendJSON(payload resendRequest) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal email: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("resend API error: status %d", resp.StatusCode)
	}
	return nil
}

// ── API Types ──

type resendRequest struct {
	From          string             `json:"from"`
	To            []string           `json:"to"`
	Subject       string             `json:"subject"`
	HTML          string             `json:"html,omitempty"`
	Attachments   []resendAttachment `json:"attachments,omitempty"`
}

type resendAttachment struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

// ── Templates ──

func safeColor(level string) string {
	switch level {
	case "critical":
		return "#dc2626"
	case "high":
		return "#ea580c"
	case "medium":
		return "#eab308"
	case "low":
		return "#22c55e"
	default:
		return "#6b7280"
	}
}

const freeScanTemplate = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"/><style>
  body{font-family:system-ui,sans-serif;background:#0a0a0a;color:#f0f0f0;margin:0;padding:40px}
  .container{max-width:600px;margin:0 auto;background:#111;border:1px solid #222;border-radius:12px;padding:40px}
  h1{color:#4ade80;font-size:24px;margin:0 0 20px}
  .score{font-size:48px;font-weight:bold;color:%s;text-align:center;padding:30px 0}
  .stats{display:flex;justify-content:space-around;padding:20px 0;border-top:1px solid #222;border-bottom:1px solid #222;margin:20px 0}
  .stat{text-align:center}
  .stat-value{font-size:28px;font-weight:bold;color:#f0f0f0}
  .stat-label{font-size:12px;color:#888;margin-top:4px}
  .cta{display:block;text-align:center;background:#4ade80;color:#0a0a0a;text-decoration:none;padding:16px;border-radius:8px;font-weight:bold;font-size:16px;margin-top:24px}
  .footer{color:#555;font-size:12px;text-align:center;margin-top:32px}
</style></head>
<body>
<div class="container">
  <h1>Undependent Scan Results</h1>
  <div class="score">%s</div>
  <p style="text-align:center;color:#888">Risk Score: %s / 100</p>
  <div class="stats">
    <div class="stat"><div class="stat-value">%s</div><div class="stat-label">Dependencies</div></div>
    <div class="stat"><div class="stat-value">%s</div><div class="stat-label">Vulnerabilities</div></div>
  </div>
  <p style="color:#888">This is a summary of your free scan. Get the full report with SBOM, remediation roadmap, and attack surface analysis.</p>
  <a class="cta" href="%s">Get Full Report — $299</a>
  <div class="footer">&copy; 2025 Undependent. All rights reserved.</div>
</div>
</body>
</html>`

const reportTemplate = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"/><style>
  body{font-family:system-ui,sans-serif;background:#0a0a0a;color:#f0f0f0;margin:0;padding:40px}
  .container{max-width:600px;margin:0 auto;background:#111;border:1px solid #222;border-radius:12px;padding:40px}
  h1{color:#4ade80;font-size:24px;margin:0 0 20px}
  .cta{display:block;text-align:center;background:#4ade80;color:#0a0a0a;text-decoration:none;padding:16px;border-radius:8px;font-weight:bold;font-size:16px;margin-top:24px}
  .footer{color:#555;font-size:12px;text-align:center;margin-top:32px}
</style></head>
<body>
<div class="container">
  <h1>Your Full Security Report</h1>
  <p style="color:#888">Your complete supply chain security report for scan <strong style="color:#f0f0f0">%s</strong> is attached as a PDF.</p>
  <p style="color:#888">The report includes dependency inventory, vulnerability details, license compatibility, and a prioritized remediation roadmap.</p>
  <p style="color:#888">For automated remediation and continuous monitoring, explore our Enterprise plan.</p>
  <a class="cta" href="%s">Enterprise Pricing</a>
  <div class="footer">&copy; 2025 Undependent. All rights reserved.</div>
</div>
</body>
</html>`

const paymentTemplate = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"/><style>
  body{font-family:system-ui,sans-serif;background:#0a0a0a;color:#f0f0f0;margin:0;padding:40px}
  .container{max-width:600px;margin:0 auto;background:#111;border:1px solid #222;border-radius:12px;padding:40px}
  h1{color:#4ade80;font-size:24px;margin:0 0 20px}
  .footer{color:#555;font-size:12px;text-align:center;margin-top:32px}
</style></head>
<body>
<div class="container">
  <h1>Payment Confirmation</h1>
  <p style="color:#888">Thank you for your purchase of <strong style="color:#f0f0f0">%s</strong> for scan <strong style="color:#f0f0f0">%s</strong>.</p>
  <p style="color:#888">Your full report will be delivered to this email within 24 hours.</p>
  <div class="footer">&copy; 2025 Undependent. All rights reserved.</div>
</div>
</body>
</html>`