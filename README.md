# Undependent — Be Undependent. Own Your Code.

Eliminate supply chain risk by absorbing third-party dependencies into your codebase. No external registries. No upstream compromise possible.

**[Try it free](https://undependent-dev.github.io/undependent-dev/) · [Documentation](https://undependent-dev.github.io/undependent-dev/#how) · [Pricing](https://undependent-dev.github.io/undependent-dev/#pricing)**

## Why

Every `go get`, `npm install`, `pip install` is a supply chain attack vector. Compromised dependencies, typosquatting, maintainer takeovers — these aren't theoretical. They happen weekly.

**Undependent eliminates the attack surface:** clone the source, absorb the code, own everything.

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│  1. ANALYZE    Scan your codebase for external dep usage    │
│  2. ABSORB     Inline dependency sources into your repo     │
│  3. VERIFY     Cryptographic integrity checks on inlined    │
│                code — detect tampering instantly            │
└─────────────────────────────────────────────────────────────┘
```

### 1. Scan

```bash
undependent scan .
```

Finds every external symbol usage across your Go, JavaScript, Python, and Rust code. Maps transitive dependencies. Detects licenses.

### 2. Inline

```bash
undependent inline .
```

Copies dependency sources into `internal/absorbed/`, updates `go.mod` with `replace` directives, generates a license manifest.

With `--pr`, creates a GitHub pull request automatically:

```bash
undependent inline . --pr
```

### 3. Verify

```bash
undependent verify .
```

Checks that inlined code matches the original module hashes. Validates `go.mod` replace directives. Confirms build integrity.

## Supported Languages

| Language | Scan | Inline | Verify |
|----------|------|--------|--------|
| Go | ✅ | ✅ | ✅ |
| JavaScript/TypeScript | ✅ | ✅ | ✅ |
| Python | ✅ | ✅ | ✅ |
| Rust | ✅ | ✅ | ✅ |

## Features

- **Dependency scanning** — Find all external symbol usage across your codebase
- **Transitive resolution** — Follow the full dependency graph (configurable depth)
- **License detection** — Identify viral licenses (GPL/AGPL) before they become a problem
- **Vulnerability scanning** — Check dependencies against OSV (Open Source Vulnerabilities) database
- **SPDX SBOM** — Generate Software Bill of Materials in SPDX format
- **PDF reports** — Full security assessment reports with remediation roadmaps
- **GitHub App** — Automatic scanning on push, inline PR creation, CI/CD integration
- **Team dashboard** — Track dependency health across all repositories
- **API access** — Programmatic scanning for CI/CD pipelines ($0.50/scan)

## Quick Start

```bash
# Install
go install github.com/undep/undep/cmd/undependent@latest

# Initialize config
undependent init

# Scan your project
undependent scan .

# Inline dependencies
undependent inline .

# Verify integrity
undependent verify .

# Generate PDF report
undependent report . --output report.pdf
```

## Configuration

`undependent init` creates `undep.yaml`:

```yaml
project:
  name: my-project
  output_dir: internal/absorbed

inline:
  max_depth: 3        # Transitive dependency depth
  skip_cgo: true      # Skip CGO packages
  skip_tests: true    # Skip test files
  allow:              # Always allow these modules
    - golang.org/x/...
  deny:               # Never inline these modules
    - github.com/huge/framework

license:
  track: true
  deny_viral: true    # Block GPL/AGPL dependencies
  output_file: LICENSE.absorbed
```

## GitHub App

Install the Undependent GitHub App for automated supply chain security:

1. **Auto-scan on push** — Every push triggers a dependency scan
2. **Inline PRs** — `undependent inline --pr` creates a PR with inlined deps
3. **CI/CD integration** — Block merges on viral licenses or critical vulnerabilities
4. **Dashboard** — Track dependency health across your organization

Set up the app with environment variables:

```bash
export GITHUB_APP_ID=your-app-id
export GITHUB_APP_INSTALLATION_ID=your-installation-id
export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----..."
export GITHUB_WEBHOOK_SECRET=your-webhook-secret
```

## Pricing

| Tier | Price | What You Get |
|------|-------|--------------|
| **Community** | Free forever | Full CLI, AGPL licensed, unlimited repos & users |
| **Pro** | $29/report | Full PDF security report, SBOM, vulnerability analysis |
| **Teams** | $199/mo | Unlimited scans, team dashboard, API access, compliance reporting |
| **Enterprise** | Custom | SSO/SAML, custom SLAs, dedicated support, on-premise deployment |

**Additional services:** GitHub App · Complimentary on Teams plan · $49/mo standalone

## API

```bash
# Create a scan (authenticated with API key)
curl -X POST https://undependent.dev/api/v1/scan \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/owner/repo"}'

# Check scan status
curl https://undependent.dev/api/scan/scan-1234567890

# Generate report (requires payment)
curl -X POST https://undependent.dev/api/report \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "scan-1234567890", "email": "you@example.com"}'
```

## Account & Authentication

```bash
# Register
curl -X POST https://undependent.dev/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "secure-password", "name": "Your Name"}'

# Login
curl -X POST https://undependent.dev/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "secure-password"}'

# Get profile (authenticated)
curl https://undependent.dev/api/user/profile \
  -H "Authorization: Bearer your-jwt-token"
```

## Security Model

- **Zero trust** — No blind trust in package registries
- **Reproducible** — Same source, same hash, same result
- **Auditable** — Every inlined dependency has a license manifest
- **Verifiable** — Cryptographic integrity checks catch tampering

## License

AGPL-3.0 for Community edition. See [LICENSE](LICENSE) for details.

---

**Undependent** — Because your code should be yours.