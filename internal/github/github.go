// Package githubapp provides GitHub App integration for webhooks, PR creation, and repo access.
package githubapp

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client wraps GitHub App API operations using raw HTTP.
type Client struct {
	appID             string
	installationID    string
	privateKey        *rsa.PrivateKey
	webhookSecret     string
	accessToken       string
	accessTokenExpiry time.Time
	http              *http.Client
}

// New creates a new GitHub App client from environment variables.
func New() (*Client, error) {
	appID := os.Getenv("GITHUB_APP_ID")
	installationID := os.Getenv("GITHUB_APP_INSTALLATION_ID")
	privateKeyPEM := os.Getenv("GITHUB_APP_PRIVATE_KEY")
	webhookSecret := os.Getenv("GITHUB_WEBHOOK_SECRET")

	if appID == "" || privateKeyPEM == "" {
		return &Client{
			appID:         appID,
			webhookSecret: webhookSecret,
			http:          &http.Client{Timeout: 30 * time.Second},
		}, nil // Allow partial init for webhook-only usage
	}

	// Parse PEM private key
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format as fallback
		genKey, err2 := x509.ParsePKCS8PrivateKey([]byte(block.Bytes))
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
		var ok bool
		privateKey, ok = genKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	}

	return &Client{
		appID:          appID,
		installationID: installationID,
		privateKey:     privateKey,
		webhookSecret:  webhookSecret,
		http:           &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// GenerateJWT creates a JWT token for GitHub App authentication.
func (c *Client) GenerateJWT() (string, error) {
	if c.privateKey == nil {
		return "", fmt.Errorf("private key not configured")
	}

	now := time.Now()
	claims := map[string]interface{}{
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": c.appID,
	}

	header := map[string]interface{}{
		"alg": "RS256",
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

	signingInput := fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString(headerJSON), base64.RawURLEncoding.EncodeToString(claimsJSON))

	signature, err := rsa.SignPKCS1v15(nil, c.privateKey, crypto.SHA256, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}

	return fmt.Sprintf("%s.%s", signingInput, base64.RawURLEncoding.EncodeToString(signature)), nil
}

// GetAccessToken exchanges a JWT for an installation access token.
func (c *Client) GetAccessToken() (string, error) {
	if c.installationID == "" || c.privateKey == nil {
		return "", fmt.Errorf("GitHub App not fully configured")
	}

	if c.accessToken != "" && time.Now().Before(c.accessTokenExpiry) {
		return c.accessToken, nil
	}

	jwt, err := c.GenerateJWT()
	if err != nil {
		return "", fmt.Errorf("generate JWT: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", c.installationID)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	c.accessToken = result.Token
	c.accessTokenExpiry = result.ExpiresAt.Add(-2 * time.Minute)
	return c.accessToken, nil
}

// HandleWebhook processes incoming GitHub webhook events.
func (c *Client) HandleWebhook(r *http.Request) (string, json.RawMessage, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", nil, fmt.Errorf("read body: %w", err)
	}

	if c.webhookSecret != "" {
		sigHeader := r.Header.Get("X-Hub-Signature-256")
		if sigHeader == "" {
			sigHeader = r.Header.Get("X-Hub-Signature")
		}
		if sigHeader == "" {
			return "", nil, fmt.Errorf("missing signature header")
		}
		if !c.verifyWebhookSignature(body, sigHeader) {
			return "", nil, fmt.Errorf("webhook signature verification failed")
		}
	}

	eventType := r.Header.Get("X-GitHub-Event")
	if eventType == "" {
		return "", nil, fmt.Errorf("missing X-GitHub-Event header")
	}

	var payload json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	return eventType, payload, nil
}

func (c *Client) verifyWebhookSignature(body []byte, sigHeader string) bool {
	parts := strings.SplitN(sigHeader, "=", 2)
	if len(parts) != 2 {
		return false
	}
	expectedHex := parts[1]

	mac := hmac.New(sha256.New, []byte(c.webhookSecret))
	mac.Write(body)
	expected := mac.Sum(nil)

	actual, err := hexDecode(expectedHex)
	if err != nil {
		return false
	}

	return hmac.Equal(expected, actual)
}

// CreatePR creates a pull request in a GitHub repository.
func (c *Client) CreatePR(owner, repo, branch, title, body string) error {
	token, err := c.GetAccessToken()
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	baseBranch := c.getDefaultBranch(owner, repo, token)

	prReq := map[string]interface{}{
		"title": title,
		"body":  body,
		"head":  branch,
		"base":  baseBranch,
	}
	prReqJSON, err := json.Marshal(prReq)
	if err != nil {
		return fmt.Errorf("marshal PR request: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls", owner, repo)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(prReqJSON)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// CreateBranch creates a new branch from a base branch.
func (c *Client) CreateBranch(owner, repo, newBranch, baseBranch string) error {
	token, err := c.GetAccessToken()
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/branches/%s", owner, repo, baseBranch)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var branchInfo struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&branchInfo); err != nil {
		return fmt.Errorf("decode branch info: %w", err)
	}

	branchReq := map[string]string{
		"ref": fmt.Sprintf("refs/heads/%s", newBranch),
		"sha": branchInfo.Commit.SHA,
	}
	branchReqJSON, _ := json.Marshal(branchReq)

	url = fmt.Sprintf("https://api.github.com/repos/%s/%s/git/refs", owner, repo)
	req, err = http.NewRequest("POST", url, strings.NewReader(string(branchReqJSON)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err = c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// GetRepoContents fetches the contents of a file in a repository.
func (c *Client) GetRepoContents(owner, repo, path, ref string) ([]byte, error) {
	token, err := c.GetAccessToken()
	if err != nil {
		return nil, fmt.Errorf("get access token: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, path)
	if ref != "" {
		url += fmt.Sprintf("?ref=%s", ref)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if result.Encoding == "base64" {
		decoded, err := base64.RawURLEncoding.DecodeString(result.Content)
		if err != nil {
			return nil, fmt.Errorf("decode base64 content: %w", err)
		}
		return decoded, nil
	}

	return []byte(result.Content), nil
}

// PushFile pushes a file to a repository on a specific branch.
func (c *Client) PushFile(owner, repo, branch, path, content, message string) error {
	token, err := c.GetAccessToken()
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s", owner, repo, path, branch)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	var sha string
	if resp.StatusCode == http.StatusOK {
		var existing struct {
			SHA string `json:"sha"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&existing); err == nil {
			sha = existing.SHA
		}
	}

	contentB64 := base64.RawURLEncoding.EncodeToString([]byte(content))
	updateReq := map[string]interface{}{
		"message": message,
		"content": contentB64,
		"branch":  branch,
	}
	if sha != "" {
		updateReq["sha"] = sha
	}

	updateReqJSON, _ := json.Marshal(updateReq)
	url = fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, path)
	req, err = http.NewRequest("PUT", url, strings.NewReader(string(updateReqJSON)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err = c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func (c *Client) getDefaultBranch(owner, repo, token string) string {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "main"
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "main"
	}
	defer resp.Body.Close()

	var result struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.DefaultBranch != "" {
		return result.DefaultBranch
	}

	return "main"
}

// ParsePushEvent extracts repo info from a push event payload.
func ParsePushEvent(payload json.RawMessage) (owner, repo, ref string, ok bool) {
	var event struct {
		Ref        string `json:"ref"`
		Repository struct {
			FullName string `json:"full_name"`
			Name     string `json:"name"`
			Owner    struct {
				Login string `json:"login"`
			} `json:"owner"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return "", "", "", false
	}

	parts := strings.SplitN(event.Ref, "/", 3)
	if len(parts) < 3 {
		return "", "", "", false
	}

	return event.Repository.Owner.Login, event.Repository.Name, parts[2], true
}

// ParseInstallationEvent extracts installation info.
func ParseInstallationEvent(payload json.RawMessage) (owner, repo, action string, ok bool) {
	var event struct {
		Action     string `json:"action"`
		Repository struct {
			Name  string `json:"name"`
			Owner struct {
				Login string `json:"login"`
			} `json:"owner"`
		} `json:"repository"`
		Installation struct {
			ID      int `json:"id"`
			Account struct {
				Login string `json:"login"`
				Type  string `json:"type"`
			} `json:"account"`
		} `json:"installation"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return "", "", "", false
	}

	return event.Installation.Account.Login, event.Repository.Name, event.Action, true
}

// hexDecode decodes a hex string to bytes.
func hexDecode(hexStr string) ([]byte, error) {
	result := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		x, err := hexDigit(hexStr[i])
		if err != nil {
			return nil, err
		}
		y, err := hexDigit(hexStr[i+1])
		if err != nil {
			return nil, err
		}
		result[i/2] = x<<4 | y
	}
	return result, nil
}

func hexDigit(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex char: %c", c)
	}
}