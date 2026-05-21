// Package python provides Python dependency inlining.
package python

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
	"regexp"
	"sort"
	"strings"
	"time"
)

// Inliner handles Python dependency inlining.
type Inliner struct {
	ProjectRoot string
	OutputDir   string
	MaxDepth    int
}

// NewInliner creates a new Python Inliner.
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

// Dependency represents a Python package to inline.
type Dependency struct {
	Name      string // package name (e.g., "requests")
	Version   string // version constraint (e.g., ">=2.28.0")
	SourceDir string // path to downloaded source
}

// Analyze scans Python source files for imports.
func (i *Inliner) Analyze() ([]string, error) {
	var imports []string
	seen := make(map[string]bool)

	// Python import patterns
	importRe := regexp.MustCompile(`(?m)^(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_]*)`)

	err := filepath.Walk(i.ProjectRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip directories
		if info.IsDir() {
			name := info.Name()
			if name == "internal" || name == ".git" || name == "node_modules" ||
				name == "__pycache__" || name == ".venv" || name == "venv" ||
				name == ".env" || name == "env" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process .py files
		if !strings.HasSuffix(path, ".py") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		matches := importRe.FindAllStringSubmatch(string(data), -1)
		for _, match := range matches {
			if len(match) > 1 {
				pkg := match[1]
				if !seen[pkg] {
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

// ResolveDependencies resolves Python dependencies from requirements.txt, pyproject.toml, or pip freeze.
func (i *Inliner) ResolveDependencies() ([]Dependency, error) {
	// Try requirements.txt first
	reqPath := filepath.Join(i.ProjectRoot, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		deps, err := i.parseRequirements(reqPath)
		if err != nil {
			return nil, err
		}
		return i.resolveTransitiveDeps(deps, 0, make(map[string]bool))
	}

	// Try pyproject.toml
	pyprojectPath := filepath.Join(i.ProjectRoot, "pyproject.toml")
	if _, err := os.Stat(pyprojectPath); err == nil {
		deps, err := i.parsePyprojectTOML(pyprojectPath)
		if err == nil && len(deps) > 0 {
			return i.resolveTransitiveDeps(deps, 0, make(map[string]bool))
		}
	}

	// Fallback: pip freeze
	deps, err := i.pipFreeze()
	if err != nil {
		return nil, err
	}
	return i.resolveTransitiveDeps(deps, 0, make(map[string]bool))
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

		dep.SourceDir = sourceDir

		// Parse the extracted source for its own dependencies
		transitiveDeps := i.parsePackageMetadata(sourceDir)

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
		if sourceDir != "" && strings.Contains(sourceDir, "undep-python-") {
			os.RemoveAll(sourceDir)
			dep.SourceDir = ""
		}
	}

	return result, nil
}

// parsePackageMetadata reads PKG-INFO, METADATA, or pyproject.toml from extracted source.
func (i *Inliner) parsePackageMetadata(sourceDir string) []Dependency {
	var deps []Dependency

	// Try METADATA file first (from extracted source distributions)
	metadataPath := filepath.Join(sourceDir, "METADATA")
	if data, err := os.ReadFile(metadataPath); err == nil {
		deps = i.parseMetadataFile(string(data))
		if len(deps) > 0 {
			return deps
		}
	}

	// Try PKG-INFO (older format)
	pkgInfoPath := filepath.Join(sourceDir, "PKG-INFO")
	if data, err := os.ReadFile(pkgInfoPath); err == nil {
		deps = i.parseMetadataFile(string(data))
		if len(deps) > 0 {
			return deps
		}
	}

	// Search subdirectories for METADATA (sometimes in .egg-info)
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return deps
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		subMeta := filepath.Join(sourceDir, entry.Name(), "METADATA")
		if data, err := os.ReadFile(subMeta); err == nil {
			deps = i.parseMetadataFile(string(data))
			if len(deps) > 0 {
				return deps
			}
		}
		subPkgInfo := filepath.Join(sourceDir, entry.Name(), "PKG-INFO")
		if data, err := os.ReadFile(subPkgInfo); err == nil {
			deps = i.parseMetadataFile(string(data))
			if len(deps) > 0 {
				return deps
			}
		}
	}

	// Try pyproject.toml in extracted source
	pyprojectPath := filepath.Join(sourceDir, "pyproject.toml")
	if _, err := os.ReadFile(pyprojectPath); err == nil {
		tomlDeps, err := i.parsePyprojectTOML(pyprojectPath)
		if err == nil && len(tomlDeps) > 0 {
			return tomlDeps
		}
	}

	// Try setup.py with simple regex
	setupPath := filepath.Join(sourceDir, "setup.py")
	if data, err := os.ReadFile(setupPath); err == nil {
		deps = i.parseSetupPy(string(data))
	}

	return deps
}

// parseMetadataFile parses Requires-Dist: lines from METADATA or PKG-INFO.
func (i *Inliner) parseMetadataFile(content string) []Dependency {
	var deps []Dependency
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Requires-Dist:") {
			depStr := strings.TrimPrefix(line, "Requires-Dist:")
			depStr = strings.TrimSpace(depStr)
			// Skip extras-only deps (contain "[")
			if strings.Contains(depStr, ";") {
				// Split on semicolon to get the base requirement
				parts := strings.SplitN(depStr, ";", 2)
				depStr = strings.TrimSpace(parts[0])
			}
			if depStr != "" && !strings.Contains(depStr, "[") {
				deps = append(deps, parsePythonDepString(depStr))
			} else if depStr != "" {
				// Strip extras like "package[extra]>=1.0"
				depStr = strings.SplitN(depStr, "[", 2)[0]
				// Re-extract version from remaining
				for _, sep := range []string{">=", "==", "<=", "<", ">", "!="} {
					idx := strings.Index(depStr, sep)
					if idx >= 0 {
						deps = append(deps, Dependency{
							Name:    strings.TrimSpace(depStr[:idx]),
							Version: sep + strings.TrimSpace(depStr[idx+len(sep):]),
						})
						break
					}
				}
			}
		}
	}

	return deps
}

// parseSetupPy extracts install_requires from setup.py using regex.
func (i *Inliner) parseSetupPy(content string) []Dependency {
	var deps []Dependency

	// Match install_requires=[..., ...] — (?s) allows . to match newlines
	re := regexp.MustCompile(`(?s)install_requires\s*=\s*\[(.*?)\]`)
	match := re.FindStringSubmatch(content)
	if len(match) < 2 {
		return deps
	}

	// Parse individual entries
	entries := match[1]
	for _, entry := range strings.Split(entries, ",") {
		entry = strings.TrimSpace(entry)
		entry = strings.Trim(entry, "\"'")
		if entry != "" && !strings.HasPrefix(entry, "#") {
			deps = append(deps, parsePythonDepString(entry))
		}
	}

	return deps
}

// parsePyprojectTOML parses dependencies from pyproject.toml (PEP 621 and Poetry).
func (i *Inliner) parsePyprojectTOML(path string) ([]Dependency, error) {
	contentBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(contentBytes)
	var deps []Dependency

	// PEP 621: [project] section with dependencies = ["pkg>=1.0", ...]
	inProject := false
	inDepsList := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)

		if trimmed == "[project]" {
			inProject = true
			continue
		}
		if inProject && strings.HasPrefix(trimmed, "[") {
			inProject = false
		}

		if inProject && strings.HasPrefix(trimmed, "dependencies") && strings.Contains(trimmed, "=") {
			inDepsList = true
			continue
		}
		if inDepsList && (strings.HasPrefix(trimmed, "[") || (trimmed != "" && !strings.HasPrefix(trimmed, "\"") && !strings.HasPrefix(trimmed, "'") && !strings.HasPrefix(trimmed, " ") && !strings.HasPrefix(trimmed, ",") && !strings.HasPrefix(trimmed, "]"))) {
			inDepsList = false
		}
		if inDepsList && trimmed == "]" {
			inDepsList = false
			continue
		}

		if inDepsList {
			// Parse list items like "requests>=2.28.0" or "flask"
			item := strings.Trim(trimmed, "\"' []")
			item = strings.TrimPrefix(item, ",")
			item = strings.TrimSpace(item)
			if item != "" && !strings.HasPrefix(item, "#") {
				deps = append(deps, parsePythonDepString(item))
			}
		}
	}

	// Poetry: [tool.poetry.dependencies]
	inPoetryDeps := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)

		if trimmed == "[tool.poetry.dependencies]" {
			inPoetryDeps = true
			continue
		}
		if inPoetryDeps && strings.HasPrefix(trimmed, "[") {
			break
		}

		if inPoetryDeps && strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.TrimSpace(parts[1])
				version = strings.Trim(version, "\"' {}")
				// Skip python itself
				if name == "python" {
					continue
				}
				deps = append(deps, Dependency{Name: name, Version: version})
			}
		}
	}

	return deps, nil
}

// parsePythonDepString parses "package>=version" or "package==version" or just "package".
func parsePythonDepString(s string) Dependency {
	s = strings.TrimSpace(s)
	for _, sep := range []string{">=", "==", "<=", "<", ">", "!="} {
		idx := strings.Index(s, sep)
		if idx >= 0 {
			return Dependency{
				Name:    strings.TrimSpace(s[:idx]),
				Version: sep + strings.TrimSpace(s[idx+len(sep):]),
			}
		}
	}
	return Dependency{Name: s, Version: ""}
}

// parseRequirements parses a requirements.txt file.
func (i *Inliner) parseRequirements(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var deps []Dependency
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Parse "package>=version" or "package==version" or just "package"
		parts := strings.Split(line, ">=")
		if len(parts) == 1 {
			parts = strings.Split(line, "==")
		}
		if len(parts) == 1 {
			parts = strings.Split(line, "<")
		}

		name := strings.TrimSpace(parts[0])
		version := ""
		if len(parts) > 1 {
			version = strings.TrimSpace(parts[1])
		}

		if name != "" {
			deps = append(deps, Dependency{Name: name, Version: version})
		}
	}

	return deps, nil
}

// pipFreeze runs pip freeze to get installed packages.
func (i *Inliner) pipFreeze() ([]Dependency, error) {
	cmd := exec.Command("pip", "freeze")
	cmd.Dir = i.ProjectRoot
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("pip freeze: %w", err)
	}

	var deps []Dependency
	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "==")
		if len(parts) == 2 {
			deps = append(deps, Dependency{
				Name:    strings.TrimSpace(parts[0]),
				Version: strings.TrimSpace(parts[1]),
			})
		}
	}

	return deps, nil
}

// DownloadSource downloads a Python package source using pip download.
func (i *Inliner) DownloadSource(dep Dependency) (string, error) {
	// Create temp directory for download
	tmpDir, err := os.MkdirTemp("", "undep-python-*")
	if err != nil {
		return "", err
	}

	// pip download --no-deps -d <dir> <package>
	pkgSpec := dep.Name
	if dep.Version != "" {
		// Normalize version spec for pip download
		version := strings.TrimPrefix(dep.Version, ">=")
		version = strings.TrimPrefix(version, "==")
		version = strings.TrimPrefix(version, "<=")
		if version != "" {
			pkgSpec = dep.Name + "==" + version
		}
	}

	cmd := exec.Command("pip", "download", "--no-deps", "--no-binary", ":none:", "-d", tmpDir, pkgSpec)
	cmd.Dir = i.ProjectRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		// Fallback: try without --no-binary
		cmd = exec.Command("pip", "download", "--no-deps", "-d", tmpDir, pkgSpec)
		cmd.Dir = i.ProjectRoot
		if out, err = cmd.CombinedOutput(); err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("pip download %s: %w: %s", pkgSpec, err, string(out))
		}
	}

	// Verify integrity if possible
	i.verifyIntegrity(dep, tmpDir)

	// Find the downloaded .tar.gz or .whl file
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	var sourceDir string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".tar.gz") {
			// Extract tar.gz
			extractDir := tmpDir + "/extracted"
			if err := os.MkdirAll(extractDir, 0755); err != nil {
				continue
			}
			cmd := exec.Command("tar", "xzf", filepath.Join(tmpDir, name), "-C", extractDir)
			if err := cmd.Run(); err != nil {
				continue
			}
			sourceDir = extractDir
			break
		} else if strings.HasSuffix(name, ".whl") {
			// Wheels are zip files
			extractDir := tmpDir + "/extracted"
			if err := os.MkdirAll(extractDir, 0755); err != nil {
				continue
			}
			cmd := exec.Command("unzip", "-o", filepath.Join(tmpDir, name), "-d", extractDir)
			if err := cmd.Run(); err != nil {
				continue
			}
			sourceDir = extractDir
			break
		}
	}

	if sourceDir == "" {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("no extractable source found for %s", dep.Name)
	}

	return sourceDir, nil
}

// verifyIntegrity checks the downloaded package against PyPI hashes.
func (i *Inliner) verifyIntegrity(dep Dependency, downloadDir string) {
	// Try to get hash from PyPI JSON API
	version := dep.Version
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, "==")
	version = strings.TrimPrefix(version, "<=")

	if version == "" {
		return
	}

	apiURL := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", dep.Name, version)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var pypiData struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
		URLs []struct {
			Packagetype string `json:"packagetype"`
			Digests     struct {
				SHA256 string `json:"sha256"`
			} `json:"digests"`
			Filename string `json:"filename"`
		} `json:"urls"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&pypiData); err != nil {
		return
	}

	// Find the expected hash for our downloaded file
	expectedHash := ""
	entries, err := os.ReadDir(downloadDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".whl") {
			// Compute SHA-256 of downloaded file
			filePath := filepath.Join(downloadDir, name)
			fileHash, err := computeFileSHA256(filePath)
			if err != nil {
				continue
			}

			// Look up expected hash from PyPI
			for _, url := range pypiData.URLs {
				if strings.Contains(name, url.Filename) || strings.HasSuffix(name, url.Filename) {
					expectedHash = url.Digests.SHA256
					break
				}
			}

			if expectedHash != "" && fileHash != "" {
				if strings.ToLower(fileHash) == strings.ToLower(expectedHash) {
					fmt.Printf("  integrity OK: %s@%s (sha256 verified)\n", dep.Name, version)
				} else {
					fmt.Printf("  integrity WARNING: %s@%s hash mismatch (expected %s, got %s)\n",
						dep.Name, version, expectedHash, fileHash)
				}
			}
			break
		}
	}
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

// Inline copies Python package sources to the output directory.
func (i *Inliner) Inline(deps []Dependency) ([]Dependency, error) {
	outputAbs := filepath.Join(i.ProjectRoot, i.OutputDir, "python")

	// Create output directory
	if err := os.MkdirAll(outputAbs, 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	var inlined []Dependency

	for _, dep := range deps {
		// Download source
		sourceDir, err := i.DownloadSource(dep)
		if err != nil {
			fmt.Printf("  warn: skip %s: %v\n", dep.Name, err)
			continue
		}

		// Copy to output directory
		destDir := filepath.Join(outputAbs, dep.Name)
		if err := i.copyPythonPackage(sourceDir, destDir); err != nil {
			os.RemoveAll(sourceDir)
			fmt.Printf("  warn: copy %s: %v\n", dep.Name, err)
			continue
		}

		dep.SourceDir = destDir
		inlined = append(inlined, dep)
		fmt.Printf("  Inlined: %s → %s\n", dep.Name, destDir)

		// Clean up temp dir
		os.RemoveAll(sourceDir)
	}

	// Rewrite imports across all inlined packages
	if len(inlined) > 0 {
		if err := i.rewriteImports(inlined, outputAbs); err != nil {
			fmt.Printf("  warn: import rewriting: %v\n", err)
		}
	}

	return inlined, nil
}

// rewriteImports rewrites import statements in inlined packages to use local paths.
func (i *Inliner) rewriteImports(deps []Dependency, outputAbs string) error {
	// Build a map of package name -> relative path within output dir
	depMap := make(map[string]string)
	for _, dep := range deps {
		rel, err := filepath.Rel(outputAbs, dep.SourceDir)
		if err != nil {
			rel = dep.Name
		}
		depMap[dep.Name] = rel
	}

	// Also build a map for dotted imports (e.g., "requests.auth" -> "requests/auth")
	depSubMap := make(map[string]string)
	for name, path := range depMap {
		depSubMap[name] = path
		// Add common subpackage mappings
		entries, err := os.ReadDir(filepath.Join(outputAbs, path))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				depSubMap[name+"."+entry.Name()] = path + "/" + entry.Name()
			}
		}
	}

	// Walk all .py files in the output directory
	return filepath.Walk(outputAbs, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() || !strings.HasSuffix(path, ".py") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		modified := false
		newContent := content

		// Rewrite "from X import Y" statements
		fromRe := regexp.MustCompile(`(?m)^(\s*)from\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s+import\s+(.*)$`)
		newContent = fromRe.ReplaceAllStringFunc(newContent, func(match string) string {
			submatches := fromRe.FindStringSubmatch(match)
			if len(submatches) < 4 {
				return match
			}
			indent := submatches[1]
			module := submatches[2]
			imports := submatches[3]

			// Check if this module is one of our inlined deps
			if targetPath, ok := depSubMap[module]; ok {
				// Convert to relative import
				relPath := strings.ReplaceAll(targetPath, "/", ".")
				return fmt.Sprintf("%sfrom .%s import %s", indent, relPath, imports)
			}

			// Check prefix match (e.g., "requests.auth" when "requests" is inlined)
			for name, targetPath := range depMap {
				if strings.HasPrefix(module, name+".") {
					relPath := strings.ReplaceAll(targetPath, "/", ".")
					submodule := strings.TrimPrefix(module, name+".")
					return fmt.Sprintf("%sfrom .%s.%s import %s", indent, relPath, submodule, imports)
				}
			}

			return match
		})

		// Rewrite "import X" statements
		importRe := regexp.MustCompile(`(?m)^(\s*)import\s+([a-zA-Z_][a-zA-Z0-9_.]*)$`)
		newContent = importRe.ReplaceAllStringFunc(newContent, func(match string) string {
			submatches := importRe.FindStringSubmatch(match)
			if len(submatches) < 3 {
				return match
			}
			indent := submatches[1]
			module := submatches[2]

			if targetPath, ok := depSubMap[module]; ok {
				relPath := strings.ReplaceAll(targetPath, "/", ".")
				return fmt.Sprintf("%sfrom .%s import %s", indent, relPath, module)
			}

			for name, targetPath := range depMap {
				if strings.HasPrefix(module, name+".") {
					relPath := strings.ReplaceAll(targetPath, "/", ".")
					submodule := strings.TrimPrefix(module, name+".")
					return fmt.Sprintf("%sfrom .%s.%s import %s", indent, relPath, submodule, submodule)
				}
			}

			return match
		})

		if newContent != content {
			modified = true
		}

		if modified {
			if err := os.WriteFile(path, []byte(newContent), 0644); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
		}

		return nil
	})
}

// copyPythonPackage copies Python source files from source to destination.
func (i *Inliner) copyPythonPackage(src, dst string) error {
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
			// Skip test directories and build artifacts
			if name == "tests" || name == "test" || name == "__pycache__" ||
				name == ".eggs" || name == "build" || name == "dist" {
				return filepath.SkipDir
			}
			return os.MkdirAll(dest, 0755)
		}

		// Only copy .py files and essential data files
		if !strings.HasSuffix(name, ".py") &&
			!strings.HasSuffix(name, ".pyi") &&
			!strings.HasSuffix(name, ".json") &&
			!strings.HasSuffix(name, ".yaml") &&
			!strings.HasSuffix(name, ".yml") &&
			!strings.HasSuffix(name, ".txt") &&
			name != "py.typed" {
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

// GenerateInitFiles creates __init__.py files for inlined packages.
func (i *Inliner) GenerateInitFiles(deps []Dependency) error {
	for _, dep := range deps {
		initPath := filepath.Join(dep.SourceDir, "__init__.py")
		if _, err := os.Stat(initPath); os.IsNotExist(err) {
			content := fmt.Sprintf("# Auto-generated by undep for %s\n", dep.Name)
			if err := os.WriteFile(initPath, []byte(content), 0644); err != nil {
				return fmt.Errorf("create __init__.py for %s: %w", dep.Name, err)
			}
		}
	}
	return nil
}

// GenerateSitePackagesConfig creates a .pth file to add inlined packages to Python path.
func (i *Inliner) GenerateSitePackagesConfig(deps []Dependency) error {
	outputAbs := filepath.Join(i.ProjectRoot, i.OutputDir, "python")
	pthPath := filepath.Join(outputAbs, "undep_absorbed.pth")

	var sb strings.Builder
	sb.WriteString("# Auto-generated by undep - adds inlined packages to Python path\n")
	sb.WriteString(outputAbs + "\n")

	return os.WriteFile(pthPath, []byte(sb.String()), 0644)
}

// sortDependencies sorts dependencies by name for deterministic output.
func sortDependencies(deps []Dependency) {
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].Name < deps[j].Name
	})
}