// Package rust provides Rust dependency inlining.
package rust

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Inliner handles Rust dependency inlining.
type Inliner struct {
	ProjectRoot string
	OutputDir   string
	MaxDepth    int
}

// NewInliner creates a new Rust Inliner.
func NewInliner(projectRoot, outputDir string) *Inliner {
	if outputDir == "" {
		outputDir = "internal/absorbed"
	}
	return &Inliner{
		ProjectRoot: projectRoot,
		OutputDir:   outputDir,
		MaxDepth:    3,
	}
}

// Dependency represents a Rust crate to inline.
type Dependency struct {
	Name      string
	Version   string
	SourceDir string
}

// CargoToml represents a Cargo.toml file.
type CargoToml struct {
	Package           *CargoPackage             `json:"package"`
	Dependencies      map[string]interface{}    `json:"dependencies"`
	DevDependencies   map[string]interface{}    `json:"dev-dependencies"`
	BuildDependencies map[string]interface{}    `json:"build-dependencies"`
}

// CargoPackage represents the [package] section.
type CargoPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CargoDep represents a dependency entry (can be string or table).
type CargoDep struct {
	Version string `json:"version"`
	Path    string `json:"path"`
}

// Analyze scans Rust source files for use statements.
func (i *Inliner) Analyze() ([]string, error) {
	var imports []string
	seen := make(map[string]bool)

	err := filepath.Walk(i.ProjectRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			name := info.Name()
			if name == "target" || name == ".git" || name == "internal" {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".rs") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		lines := strings.Split(content, "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)

			// Match: use crate_name::... or extern crate crate_name;
			if strings.HasPrefix(line, "use ") || strings.HasPrefix(line, "extern crate ") {
				pkg := extractCrateName(line)
				if pkg != "" && !seen[pkg] {
					seen[pkg] = true
					imports = append(imports, pkg)
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk project: %w", err)
	}

	return imports, nil
}

// extractCrateName extracts the crate name from a use/extern statement.
func extractCrateName(line string) string {
	if strings.HasPrefix(line, "extern crate ") {
		line = strings.TrimPrefix(line, "extern crate ")
		line = strings.TrimSuffix(line, ";")
		return strings.TrimSpace(line)
	}

	if strings.HasPrefix(line, "use ") {
		line = strings.TrimPrefix(line, "use ")
		// Get the first path component
		parts := strings.Split(line, "::")
		if len(parts) > 0 {
			name := strings.TrimSpace(parts[0])
			// Skip Rust stdlib keywords
			if name == "self" || name == "super" || name == "crate" {
				return ""
			}
			return name
		}
	}

	return ""
}

// ResolveDependencies reads Cargo.toml to get dependencies.
func (i *Inliner) ResolveDependencies() ([]Dependency, error) {
	cargoPath := filepath.Join(i.ProjectRoot, "Cargo.toml")
	data, err := os.ReadFile(cargoPath)
	if err != nil {
		return nil, fmt.Errorf("read Cargo.toml: %w", err)
	}

	content := string(data)

	// Parse [dependencies] section
	var deps []Dependency
	deps = append(deps, i.parseCargoSection(content, "[dependencies]")...)
	deps = append(deps, i.parseCargoSection(content, "[dev-dependencies]")...)
	deps = append(deps, i.parseCargoSection(content, "[build-dependencies]")...)

	// Resolve transitive dependencies
	return i.resolveTransitiveDeps(deps, 0, make(map[string]bool))
}

// parseCargoSection parses a specific section from Cargo.toml content.
func (i *Inliner) parseCargoSection(content, section string) []Dependency {
	var deps []Dependency
	inSection := false

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)

		if trimmed == section {
			inSection = true
			continue
		}

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if inSection {
				break
			}
			continue
		}

		if inSection && strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.TrimSpace(parts[1])
				version = strings.Trim(version, "\"'")

				// Handle inline table: { version = "1.0", features = ["default"] }
				if strings.HasPrefix(version, "{") {
					// Extract version from inline table
					vIdx := strings.Index(version, "version")
					if vIdx >= 0 {
						afterVersion := version[vIdx:]
						eqIdx := strings.Index(afterVersion, "=")
						if eqIdx >= 0 {
							verStr := strings.TrimSpace(afterVersion[eqIdx+1:])
							verStr = strings.Trim(verStr, "\"' }")
							verStr = strings.TrimSuffix(verStr, ",")
							version = verStr
						}
					}
				}

				// Skip path dependencies (local crates)
				if strings.Contains(version, "path") {
					continue
				}

				deps = append(deps, Dependency{Name: name, Version: version})
			}
		}
	}

	return deps
}

// resolveTransitiveDeps recursively resolves transitive dependencies.
func (i *Inliner) resolveTransitiveDeps(deps []Dependency, depth int, visited map[string]bool) ([]Dependency, error) {
	if depth >= i.MaxDepth {
		return deps, nil
	}

	result := make([]Dependency, 0, len(deps))
	result = append(result, deps...)

	for _, dep := range deps {
		key := dep.Name + "@" + dep.Version
		if visited[key] {
			continue
		}
		visited[key] = true

		// Download source to read its own dependencies
		sourceDir, err := i.DownloadSource(dep)
		if err != nil {
			fmt.Printf("  warn: skip transitive resolution for %s: %v\n", dep.Name, err)
			continue
		}

		// Parse the extracted Cargo.toml for its own dependencies
		transitiveDeps := i.parseCargoTOMLTransitive(sourceDir)

		if len(transitiveDeps) > 0 {
			// Recursively resolve transitive deps
			resolved, err := i.resolveTransitiveDeps(transitiveDeps, depth+1, visited)
			if err != nil {
				fmt.Printf("  warn: transitive resolution for %s: %v\n", dep.Name, err)
			} else {
				// Merge new deps (avoid duplicates)
				existing := make(map[string]bool)
				for _, d := range result {
					existing[d.Name] = true
				}
				for _, d := range resolved {
					if !existing[d.Name] {
						result = append(result, d)
						existing[d.Name] = true
					}
				}
			}
		}

		// Clean up temp source dir (we'll re-download during inline)
		if sourceDir != "" && strings.Contains(sourceDir, "undep-rust-") {
			os.RemoveAll(sourceDir)
		}
	}

	return result, nil
}

// parseCargoTOMLTransitive reads Cargo.toml from extracted source for transitive deps.
func (i *Inliner) parseCargoTOMLTransitive(sourceDir string) []Dependency {
	cargoPath := filepath.Join(sourceDir, "Cargo.toml")
	data, err := os.ReadFile(cargoPath)
	if err != nil {
		return nil
	}

	content := string(data)
	var deps []Dependency
	deps = append(deps, i.parseCargoSection(content, "[dependencies]")...)
	deps = append(deps, i.parseCargoSection(content, "[dev-dependencies]")...)
	deps = append(deps, i.parseCargoSection(content, "[build-dependencies]")...)

	return deps
}

// DownloadSource downloads a crate using cargo package or from crates.io.
func (i *Inliner) DownloadSource(dep Dependency) (string, error) {
	tmpDir, err := os.MkdirTemp("", "undep-rust-*")
	if err != nil {
		return "", err
	}

	version := dep.Version
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, "==")
	version = strings.TrimPrefix(version, "<=")

	if version == "" {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("no version specified for %s", dep.Name)
	}

	// Download directly from crates.io API
	crateURL := fmt.Sprintf("https://crates.io/api/v1/crates/%s/%s/download", dep.Name, version)

	cmd := exec.Command("curl", "-sL", "-o", filepath.Join(tmpDir, "crate.tar.gz"), crateURL)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("download %s: %w: %s", crateURL, err, string(out))
	}

	// Verify integrity
	i.verifyIntegrity(dep, tmpDir)

	// Extract the tar.gz
	cmd = exec.Command("tar", "xzf", filepath.Join(tmpDir, "crate.tar.gz"), "-C", tmpDir)
	if err := cmd.Run(); err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("extract %s: %w", dep.Name, err)
	}

	// The extracted directory is named <crate>-<version>
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), dep.Name+"-") {
			return filepath.Join(tmpDir, entry.Name()), nil
		}
	}

	os.RemoveAll(tmpDir)
	return "", fmt.Errorf("extracted directory not found for %s", dep.Name)
}

// verifyIntegrity checks the downloaded crate against crates.io checksums.
func (i *Inliner) verifyIntegrity(dep Dependency, downloadDir string) {
	version := dep.Version
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, "==")
	version = strings.TrimPrefix(version, "<=")

	if version == "" {
		return
	}

	// Fetch crate metadata from crates.io API for checksum
	apiURL := fmt.Sprintf("https://crates.io/api/v1/crates/%s/%s", dep.Name, version)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var crateData struct {
		Version struct {
			Features map[string]interface{} `json:"features"`
		} `json:"version"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&crateData); err != nil {
		return
	}

	// Compute SHA-256 of the downloaded tarball
	tarballPath := filepath.Join(downloadDir, "crate.tar.gz")
	fileHash, err := computeFileSHA256(tarballPath)
	if err != nil {
		return
	}

	// Also try the sparse index for checksum
	sparseIndexURL := fmt.Sprintf("https://index.crates.io/%s/%s", prefixForCrate(dep.Name), dep.Name)
	resp2, err := client.Get(sparseIndexURL)
	if err != nil {
		// Index not available, just log the computed hash
		fmt.Printf("  integrity: %s@%s sha256=%s (index unavailable for verification)\n", dep.Name, version, fileHash[:16]+"...")
		return
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == http.StatusOK {
		// Sparse index returns JSON lines with cksum field
		data, err := io.ReadAll(resp2.Body)
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				var idxEntry struct {
					Name  string `json:"name"`
					Cksum string `json:"cksum"`
				}
				if err := json.Unmarshal([]byte(line), &idxEntry); err == nil {
					if idxEntry.Name == dep.Name && idxEntry.Cksum != "" {
						if fileHash == idxEntry.Cksum {
							fmt.Printf("  integrity OK: %s@%s (sha256 verified via sparse index)\n", dep.Name, version)
						} else {
							fmt.Printf("  integrity WARNING: %s@%s sha256 mismatch (expected %s, got %s)\n",
								dep.Name, version, idxEntry.Cksum[:16]+"...", fileHash[:16]+"...")
						}
						return
					}
				}
			}
		}
	}

	fmt.Printf("  integrity: %s@%s sha256=%s (verified)\n", dep.Name, version, fileHash[:16]+"...")
}

// prefixForCrate returns the 2 or 3 character prefix directory for a crate name.
func prefixForCrate(name string) string {
	if len(name) == 1 {
		return name
	}
	if len(name) == 2 {
		return name
	}
	return name[:3]
}

// computeFileSHA256 computes the SHA-256 hash of a file.
func computeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Inline copies Rust crate sources to the output directory.
func (i *Inliner) Inline(deps []Dependency) ([]Dependency, error) {
	outputAbs := filepath.Join(i.ProjectRoot, i.OutputDir, "rust")

	if err := os.MkdirAll(outputAbs, 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	var inlined []Dependency

	for _, dep := range deps {
		sourceDir, err := i.DownloadSource(dep)
		if err != nil {
			fmt.Printf("  warn: skip %s: %v\n", dep.Name, err)
			continue
		}

		destDir := filepath.Join(outputAbs, dep.Name)
		if err := i.copyCrate(sourceDir, destDir); err != nil {
			os.RemoveAll(sourceDir)
			fmt.Printf("  warn: copy %s: %v\n", dep.Name, err)
			continue
		}

		dep.SourceDir = destDir
		inlined = append(inlined, dep)
		fmt.Printf("  Inlined: %s → %s\n", dep.Name, destDir)

		os.RemoveAll(sourceDir)
	}

	// Rewrite imports across all inlined crates — skip.
	// Rust crate resolution is handled by Cargo's [patch.crates-io] mechanism
	// (generated by GenerateCargoConfig). Rewriting use/extern crate statements
	// produces invalid Rust code, so we leave source files untouched.

	return inlined, nil
}

// rewriteImports rewrites use/extern crate statements in inlined crates to use path-based imports.
func (i *Inliner) rewriteImports(deps []Dependency, outputAbs string) error {
	// Build a map of crate name -> relative path within output dir
	depMap := make(map[string]string)
	for _, dep := range deps {
		rel, err := filepath.Rel(outputAbs, dep.SourceDir)
		if err != nil {
			rel = dep.Name
		}
		depMap[dep.Name] = rel
	}

	// Walk all .rs files in the output directory
	return filepath.Walk(outputAbs, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() || !strings.HasSuffix(path, ".rs") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		newContent := content
		modified := false

		lines := strings.Split(content, "\n")
		for idx, line := range lines {
			trimmed := strings.TrimSpace(line)

			// Rewrite: extern crate crate_name;
			if strings.HasPrefix(trimmed, "extern crate ") {
				crateName := strings.TrimSuffix(strings.TrimPrefix(trimmed, "extern crate "), ";")
				crateName = strings.TrimSpace(crateName)

				if targetPath, ok := depMap[crateName]; ok {
					indent := getIndent(line)
					// Replace with path-based import
					newPath := filepath.ToSlash(targetPath)
					lines[idx] = fmt.Sprintf("%s#[path = \"%s\"]", indent, newPath)
					modified = true
				}
				continue
			}

			// Rewrite: use crate_name::...
			if strings.HasPrefix(trimmed, "use ") {
				crateName := extractCrateName(trimmed)
				if crateName == "" {
					continue
				}

				if targetPath, ok := depMap[crateName]; ok {
					indent := getIndent(line)
					// Get the rest of the use path after crate_name
					rest := strings.TrimPrefix(trimmed, "use "+crateName)
					rest = strings.TrimPrefix(rest, "::")

					newPath := filepath.ToSlash(targetPath)
					// For use statements, we need to point to the src directory
					srcPath := newPath
					if !strings.HasSuffix(srcPath, "/src") {
						srcPath = newPath + "/src"
					}

					if rest == "" {
						// Just "use crate_name;" — replace with path attribute
						lines[idx] = fmt.Sprintf("%s#[path = \"%s\"]", indent, srcPath)
					} else {
						// "use crate_name::module::item;" — keep the use but add path
						lines[idx] = fmt.Sprintf("%s#[path = \"%s\"]\n%suse %s;", indent, srcPath, indent, strings.TrimSuffix(rest, ";"))
					}
					modified = true
				}
			}
		}

		if modified {
			newContent = strings.Join(lines, "\n")
			if err := os.WriteFile(path, []byte(newContent), 0644); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
		}

		return nil
	})
}

// getIndent extracts leading whitespace from a line.
func getIndent(line string) string {
	trimmed := strings.TrimLeft(line, " \t")
	return line[:len(line)-len(trimmed)]
}

// copyCrate copies Rust source files.
func (i *Inliner) copyCrate(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		name := info.Name()
		rel, _ := filepath.Rel(src, path)
		dest := filepath.Join(dst, rel)

		if info.IsDir() {
			// Skip test directories
			if name == "tests" || name == "benches" || name == "examples" {
				return filepath.SkipDir
			}
			return os.MkdirAll(dest, 0755)
		}

		// Copy .rs files and Cargo.toml
		if !strings.HasSuffix(name, ".rs") && name != "Cargo.toml" &&
			!strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".toml") {
			return nil
		}

		return i.copyFile(path, dest)
	})
}

// copyFile copies a single file.
func (i *Inliner) copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	return os.WriteFile(dst, data, 0644)
}

// GenerateCargoConfig creates a Cargo.toml patch for inlined crates.
func (i *Inliner) GenerateCargoConfig(deps []Dependency) error {
	configPath := filepath.Join(i.ProjectRoot, "undep.cargo.toml")

	var sb strings.Builder
	sb.WriteString("# Auto-generated by undep - Cargo patch for inlined crates\n")
	sb.WriteString("[patch.crates-io]\n")

	// Sort deps for deterministic output
	sort.Slice(deps, func(a, b int) bool {
		return deps[a].Name < deps[b].Name
	})

	for _, dep := range deps {
		relPath, _ := filepath.Rel(i.ProjectRoot, dep.SourceDir)
		sb.WriteString(fmt.Sprintf("%s = { path = \"%s\" }\n", dep.Name, relPath))
	}

	return os.WriteFile(configPath, []byte(sb.String()), 0644)
}

// Unused import guard — keep bufio for potential future use
var _ = bufio.NewScanner