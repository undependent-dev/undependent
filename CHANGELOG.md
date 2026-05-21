# Changelog

All notable changes to Undependent are documented here.

## [1.0.0] - 2025-05-20

### Added
- Dependency sovereignty: absorb third-party deps into your codebase
- Lockfile integrity: SHA256 hashes of every inlined file
- CVE scanning via OSV API integration
- Attack surface mapping: see which YOUR files import inlined deps
- License compliance: auto-detect project license, check compatibility
- SBOM generation (CycloneDX + SPDX)
- Multi-language support: Go, Python, JavaScript/TypeScript, Rust (beta)
- AGPL v3 dual-license model with commercial options
- Project license auto-detection (AGPL/GPL/MIT/Apache/BSD/ISC/MPL)
- Viral license compatibility checking

### Commands
- `undep init` — Create configuration
- `undep analyze` — Scan dependencies and symbol usage
- `undep inline` — Absorb dependencies into codebase
- `undep verify` — Validate build, integrity, CVE status
- `undep diff` — Compare current state against lockfile
- `undep report` — Generate SBOM, SPDX, license manifest
- `undep status` — Show current dependency state
- `undep attack-surface` — Map which files import inlined deps

### Architecture
- Go core with language-specific inliners
- Transitive dependency resolution
- Symbol-level usage analysis
- Lockfile-based integrity verification
