# Undependent — Be Undependent. Own Your Code.

Eliminate supply chain risk by absorbing third-party dependencies into your codebase. No external registries. No upstream compromise possible.

**[Try it free](https://undependent-dev.github.io/undependent-dev/) · [Documentation](https://undependent-dev.github.io/undependent-dev/#how) · [Pricing](https://undependent-dev.github.io/undependent-dev/#pricing)**

## Quick Start

### Install

```bash
# Download the binary for your platform
curl -sL https://github.com/undependent-dev/undependent/releases/latest/download/undep-linux-amd64 -o undep
chmod +x undep
sudo mv undep /usr/local/bin/
```

Or build from source:

```bash
go build -o undep ./cmd/undep
```

### Use

```bash
# Analyze your dependencies
undep analyze

# Inline them into your codebase
undep inline --pr

# Verify integrity
undep verify
```

That's it. Your dependencies are now part of your code. No more trusting external registries.

## How It Works

1. **Analyze** — Scan your codebase to identify every third-party dependency
2. **Absorb** — Inline the dependencies you need directly into your codebase
3. **Verify** — Validate integrity with SHA256 hashes, scan for CVEs
4. **Automate** — Integrate into CI/CD for ongoing protection

## Pricing

| Tier | Price | What You Get |
|------|-------|-------------|
| **Community** | Free forever | Full CLI, AGPL licensed, unlimited repos & users |
| **Single Scan** | $99/repo | One-time cloud scan, full PDF report, SBOM export |
| **Commercial** | $299/yr | Commercial license (no AGPL), unlimited users & repos |
| **Monitoring** | Add-on | Daily CVE monitoring, Slack/Discord alerts |
| **Enterprise** | Custom | Volume licensing, SSO, on-prem, dedicated support |

**Additional services:** GitHub App · Compliance Dashboard · Air-Gapped Solutions

[Compare with Snyk, Dependabot, Socket →](https://undependent-dev.github.io/undependent-dev/#compare)

## License

Community edition: **AGPL v3**
Commercial license: Available at [undependent.dev](https://undependent-dev.github.io/undependent-dev/#pricing)
