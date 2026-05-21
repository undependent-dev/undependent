// Package payment handles Stripe integration for report purchases and subscriptions.
package payment

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Client wraps Stripe API operations using raw HTTP (avoids SDK versioning issues).
type Client struct {
	secretKey     string
	webhookSecret string
	http          *http.Client
}

// New creates a new Stripe client from environment.
func New() *Client {
	return &Client{
		secretKey:     os.Getenv("STRIPE_SECRET_KEY"),
		webhookSecret: os.Getenv("STRIPE_WEBHOOK_SECRET"),
		http:          &http.Client{},
	}
}

// CreatePaymentLink creates a Stripe Checkout session for a $299 report.
// Returns the checkout URL.
func (c *Client) CreatePaymentLink(scanID, email string) (string, error) {
	form := url.Values{}
	form.Set("mode", "payment")
	form.Set("success_url", "https://undependent.dev/scan/"+scanID+"?status=payment_success")
	form.Set("cancel_url", "https://undependent.dev/scan/"+scanID+"?status=payment_cancelled")
	form.Set("customer_email", email)
	form.Set("metadata[scan_id]", scanID)

	// Line item
	lineItem := map[string]interface{}{
		"price_data": map[string]interface{}{
			"currency":     "usd",
			"unit_amount":  29900, // $299.00 in cents
			"product_data": map[string]string{
				"name":        "Undependent Full Security Report",
				"description": "Complete PDF report with SBOM, vulnerability analysis, and remediation roadmap",
			},
		},
		"quantity": 1,
	}
	lineItemJSON, _ := json.Marshal(lineItem)
	form.Set("line_items[0]", string(lineItemJSON))

	req, err := http.NewRequest("POST", "https://api.stripe.com/v1/checkout/sessions", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(c.secretKey, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("stripe API error %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		URL string `json:"url"`
		ID  string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	return result.URL, nil
}

// stripeEvent represents a webhook event.
type stripeEvent struct {
	Type string `json:"type"`
	Data struct {
		Raw json.RawMessage `json:"raw"`
	} `json:"data"`
}

// HandleWebhook processes Stripe webhook events.
// Returns the scan ID if a payment was completed, or empty string otherwise.
func (c *Client) HandleWebhook(r *http.Request) (string, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	sigHeader := r.Header.Get("Stripe-Signature")
	if sigHeader == "" {
		return "", fmt.Errorf("missing Stripe-Signature header")
	}

	// Verify signature using Stripe's algorithm
	if !c.verifySignature(body, sigHeader) {
		return "", fmt.Errorf("webhook signature verification failed")
	}

	var event stripeEvent
	if err := json.Unmarshal(body, &event); err != nil {
		return "", fmt.Errorf("unmarshal event: %w", err)
	}

	if event.Type == "checkout.session.completed" {
		var session struct {
			Metadata map[string]string `json:"metadata"`
		}
		if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
			return "", fmt.Errorf("unmarshal session: %w", err)
		}
		return session.Metadata["scan_id"], nil
	}

	return "", nil
}

// verifySignature checks the Stripe webhook signature using HMAC-SHA256.
// Implements Stripe's signature verification algorithm per their docs.
func (c *Client) verifySignature(body []byte, sigHeader string) bool {
	if c.webhookSecret == "" {
		// No webhook secret configured — skip verification (dev mode)
		return true
	}

	// Parse signature: t=timestamp,v1=signature,v2=signature
	parts := strings.Split(sigHeader, ",")
	var timestamp int64
	var v1Sig string
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			switch kv[0] {
			case "t":
				var err error
				timestamp, err = strconv.ParseInt(kv[1], 10, 64)
				if err != nil {
					return false
				}
			case "v1":
				v1Sig = kv[1]
			}
		}
	}

	if v1Sig == "" {
		return false
	}

	// Timestamp tolerance: 5 minutes (300 seconds)
	if int64(time.Now().Unix())-timestamp > 300 {
		return false
	}

	// Compute expected signature: HMAC-SHA256(timestamp || payload, secret)
	payload := fmt.Sprintf("%d.%s", timestamp, string(body))
	mac := hmac.New(sha256.New, []byte(c.webhookSecret))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(v1Sig), []byte(expectedSig))
}
// CreateSubscriptionLink creates a Stripe Checkout session for Teams subscription ($199/mo).
// Returns the checkout URL.
func (c *Client) CreateSubscriptionLink(email, repoURL string) (string, error) {
	form := url.Values{}
	form.Set("mode", "subscription")
	form.Set("success_url", "https://undependent.dev/dashboard?status=subscription_success")
	form.Set("cancel_url", "https://undependent.dev/pricing?status=subscription_cancelled")
	form.Set("customer_email", email)
	form.Set("metadata[repo_url]", repoURL)
	form.Set("allow_promotion_codes", "true")

	// Subscription line item
	lineItem := map[string]interface{}{
		"price_data": map[string]interface{}{
			"currency":     "usd",
			"unit_amount":  19900, // $199.00 in cents
			"recurring":    map[string]interface{}{"interval": "month"},
			"product_data": map[string]string{
				"name":        "Undependent Teams",
				"description": "Unlimited scans, CI/CD integration, team dashboard, API access, compliance reporting",
			},
		},
		"quantity": 1,
	}
	lineItemJSON, _ := json.Marshal(lineItem)
	form.Set("line_items[0]", string(lineItemJSON))

	req, err := http.NewRequest("POST", "https://api.stripe.com/v1/checkout/sessions", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(c.secretKey, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("stripe API error %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		URL string `json:"url"`
		ID  string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	return result.URL, nil
}

// HandleSubscriptionWebhook processes subscription-related webhook events.
// Returns the subscription ID and customer email if a subscription was created.
func (c *Client) HandleSubscriptionWebhook(r *http.Request) (string, string, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", "", fmt.Errorf("read body: %w", err)
	}

	sigHeader := r.Header.Get("Stripe-Signature")
	if sigHeader == "" {
		return "", "", fmt.Errorf("missing Stripe-Signature header")
	}

	if !c.verifySignature(body, sigHeader) {
		return "", "", fmt.Errorf("webhook signature verification failed")
	}

	var event stripeEvent
	if err := json.Unmarshal(body, &event); err != nil {
		return "", "", fmt.Errorf("unmarshal event: %w", err)
	}

	if event.Type == "checkout.session.completed" {
		var session struct {
			Subscription string `json:"subscription"`
			Customer     string `json:"customer"`
			Metadata     map[string]string `json:"metadata"`
			Mode         string `json:"mode"`
		}
		if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
			return "", "", fmt.Errorf("unmarshal session: %w", err)
		}
		if session.Mode == "subscription" {
			return session.Subscription, session.Metadata["repo_url"], nil
		}
	}

	if event.Type == "customer.subscription.updated" || event.Type == "customer.subscription.deleted" {
		var sub struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
			return "", "", fmt.Errorf("unmarshal subscription: %w", err)
		}
		return sub.ID, "", nil
	}

	return "", "", nil
}
