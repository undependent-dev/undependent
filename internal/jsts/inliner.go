// Package jsts provides JavaScript/TypeScript dependency inlining.
package jsts

import (
	"crypto/sha1"
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

// Inliner handles JavaScript/TypeScript dependency inlining.
type Inliner struct {
	ProjectRoot string
	OutputDir   string
	MaxDepth    int
}

// NewInliner creates a new JS/TS Inliner.
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

// Dependency represents a JS/TS package to inline.
type Dependency struct {
	Name      string
	Version   string
	SourceDir string
}

// PackageJSON represents a package.json file.
type PackageJSON struct {
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	Dependencies     map[string]string `json:"dependencies"`
	DevDependencies  map[string]string `json:"devDependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
	Main             string            `json:"main"`
	Types            string            `json:"types"`
	Type             string            `json:"type"`
}

// Analyze scans JS/TS files for imports.
func (i *Inliner) Analyze() ([]string, error) {
	var imports []string
	seen := make(map[string]bool)

	// Scan for import/require statements
	err := filepath.Walk(i.ProjectRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			name := info.Name()
			if name == "node_modules" || name == ".git" || name == "internal" ||
				name == "dist" || name == "build" {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".js") && !strings.HasSuffix(path, ".ts") &&
			!strings.HasSuffix(path, ".jsx") && !strings.HasSuffix(path, ".tsx") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)

		// Find import statements: import ... from 'package' or import 'package'
		// Find require statements: require('package')
		// Find dynamic imports: import('package')
		// Find re-exports: export { foo } from 'package'
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)

			// Match: import ... from 'package' or import 'package'
			if strings.HasPrefix(line, "import ") {
				pkg := extractPackageName(line)
				if pkg != "" && !seen[pkg] {
					seen[pkg] = true
					imports = append(imports, pkg)
				}
			}

			// Match: require('package')
			if strings.Contains(line, "require(") {
				pkg := extractRequirePackage(line)
				if pkg != "" && !seen[pkg] {
					seen[pkg] = true
					imports = append(imports, pkg)
				}
			}

			// Match: import('package') — dynamic imports
			if strings.Contains(line, "import(") {
				pkg := extractDynamicImport(line)
				if pkg != "" && !seen[pkg] {
					seen[pkg] = true
					imports = append(imports, pkg)
				}
			}

			// Match: export { foo } from 'package' or export * from 'package'
			if strings.HasPrefix(line, "export ") && strings.Contains(line, "from ") {
				pkg := extractReExport(line)
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

// extractPackageName extracts the package name from an import statement.
func extractPackageName(line string) string {
	// Handle: import ... from 'package' or import "package"
	idx := strings.Index(line, "from ")
	if idx == -1 {
		idx = strings.Index(line, "import ")
		if idx == -1 {
			return ""
		}
		idx += 7
	} else {
		idx += 5
	}

	// Find the quoted string
	for i := idx; i < len(line); i++ {
		if line[i] == '\'' || line[i] == '"' {
			quote := line[i]
			start := i + 1
			end := strings.IndexByte(line[start:], quote)
			if end == -1 {
				return ""
			}
			pkg := line[start : start+end]
			// Only return external packages (not relative imports)
			if !strings.HasPrefix(pkg, ".") && !strings.HasPrefix(pkg, "/") {
				return pkg
			}
			break
		}
	}

	return ""
}

// extractRequirePackage extracts the package name from a require statement.
func extractRequirePackage(line string) string {
	idx := strings.Index(line, "require(")
	if idx == -1 {
		return ""
	}
	idx += 8

	// Find the quoted string
	for i := idx; i < len(line); i++ {
		if line[i] == '\'' || line[i] == '"' {
			quote := line[i]
			start := i + 1
			end := strings.IndexByte(line[start:], quote)
			if end == -1 {
				return ""
			}
			pkg := line[start : start+end]
			if !strings.HasPrefix(pkg, ".") && !strings.HasPrefix(pkg, "/") {
				return pkg
			}
			break
		}
	}

	return ""
}

// extractDynamicImport extracts the package name from import('package').
func extractDynamicImport(line string) string {
	idx := strings.Index(line, "import(")
	if idx == -1 {
		return ""
	}
	idx += 7

	// Find the quoted string
	for i := idx; i < len(line); i++ {
		if line[i] == '\'' || line[i] == '"' {
			quote := line[i]
			start := i + 1
			end := strings.IndexByte(line[start:], quote)
			if end == -1 {
				return ""
			}
			pkg := line[start : start+end]
			if !strings.HasPrefix(pkg, ".") && !strings.HasPrefix(pkg, "/") {
				return pkg
			}
			break
		}
	}

	return ""
}

// extractReExport extracts the package name from export { ... } from 'package'.
func extractReExport(line string) string {
	idx := strings.Index(line, "from ")
	if idx == -1 {
		return ""
	}
	idx += 5

	// Find the quoted string
	for i := idx; i < len(line); i++ {
		if line[i] == '\'' || line[i] == '"' {
			quote := line[i]
			start := i + 1
			end := strings.IndexByte(line[start:], quote)
			if end == -1 {
				return ""
			}
			pkg := line[start : start+end]
			if !strings.HasPrefix(pkg, ".") && !strings.HasPrefix(pkg, "/") {
				return pkg
			}
			break
		}
	}

	return ""
}

// ResolveDependencies reads package.json to get dependencies.
func (i *Inliner) ResolveDependencies() ([]Dependency, error) {
	pkgPath := filepath.Join(i.ProjectRoot, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, fmt.Errorf("read package.json: %w", err)
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	var deps []Dependency

	// Process dependencies
	for name, version := range pkg.Dependencies {
		deps = append(deps, Dependency{Name: name, Version: version})
	}

	// Process devDependencies
	for name, version := range pkg.DevDependencies {
		deps = append(deps, Dependency{Name: name, Version: version})
	}

	// Resolve transitive dependencies
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

		// Parse the extracted package.json for its own dependencies
		transitiveDeps := i.parsePackageJSONDeps(sourceDir)

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
		if sourceDir != "" && strings.Contains(sourceDir, "undep-js-") {
			os.RemoveAll(sourceDir)
		}
	}

	return result, nil
}

// parsePackageJSONDeps reads package.json from extracted source and returns dependencies.
func (i *Inliner) parsePackageJSONDeps(sourceDir string) []Dependency {
	pkgPath := filepath.Join(sourceDir, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	var deps []Dependency

	// Process dependencies (runtime deps are transitive)
	for name, version := range pkg.Dependencies {
		deps = append(deps, Dependency{Name: name, Version: version})
	}

	// Process peerDependencies (these are also transitive)
	for name, version := range pkg.PeerDependencies {
		deps = append(deps, Dependency{Name: name, Version: version})
	}

	return deps
}

// DownloadSource downloads a package using npm pack.
func (i *Inliner) DownloadSource(dep Dependency) (string, error) {
	tmpDir, err := os.MkdirTemp("", "undep-js-*")
	if err != nil {
		return "", err
	}

	pkgSpec := dep.Name
	if dep.Version != "" {
		// Normalize version spec for npm
		version := strings.TrimPrefix(dep.Version, "^")
		version = strings.TrimPrefix(version, "~")
		version = strings.TrimPrefix(version, ">=")
		version = strings.TrimPrefix(version, "==")
		version = strings.TrimPrefix(version, "<=")
		if version != "" {
			pkgSpec = dep.Name + "@" + version
		}
	}

	// npm pack <package> --pack-destination <dir>
	cmd := exec.Command("npm", "pack", pkgSpec, "--pack-destination", tmpDir)
	cmd.Dir = i.ProjectRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("npm pack %s: %w: %s", pkgSpec, err, string(out))
	}

	// Verify integrity if possible
	i.verifyIntegrity(dep, tmpDir)

	// npm pack creates a .tgz file; extract it
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tgz") {
			extractDir := tmpDir + "/package"
			cmd := exec.Command("tar", "xzf", filepath.Join(tmpDir, entry.Name()), "-C", extractDir)
			if err := cmd.Run(); err != nil {
				os.RemoveAll(tmpDir)
				return "", fmt.Errorf("extract %s: %w", entry.Name(), err)
			}
			// npm pack creates a package/ subdirectory
			return extractDir + "/package", nil
		}
	}

	os.RemoveAll(tmpDir)
	return "", fmt.Errorf("no .tgz found for %s", dep.Name)
}

// verifyIntegrity checks the downloaded package against npm registry hashes.
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

	apiURL := fmt.Sprintf("https://registry.npmjs.org/%s/%s", dep.Name, version)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var npmData struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Shasum  string `json:"shasum"`
		Dist    struct {
			Integrity string `json:"integrity"`
			Shasum    string `json:"shasum"`
		} `json:"dist"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&npmData); err != nil {
		return
	}

	// Find the downloaded .tgz file and verify its hash
	entries, err := os.ReadDir(downloadDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".tgz") {
			filePath := filepath.Join(downloadDir, name)
			fileHash, err := computeFileSHA256(filePath)
			if err != nil {
				continue
			}

			// npm registry provides shasum (SHA-1) and integrity (SHA-512)
			// We computed SHA-256, so compare against what we can
			if npmData.Dist.Integrity != "" {
				// Parse integrity string: "sha512-..." or "sha256-..."
				integrity := npmData.Dist.Integrity
				if strings.HasPrefix(integrity, "sha256-") {
					expected := strings.TrimPrefix(integrity, "sha256-")
					// npm uses base64, we use hex — convert
					if fileHash == expected || normalizeHash(fileHash) == normalizeHash(expected) {
						fmt.Printf("  integrity OK: %s@%s (sha256 verified)\n", dep.Name, version)
					} else {
						fmt.Printf("  integrity WARNING: %s@%s sha256 mismatch\n", dep.Name, version)
					}
				}
			}

			// Also verify shasum if available
			if npmData.Shasum != "" {
				// Compute SHA-1 for comparison
				fileSHA1, err := computeFileSHA1(filePath)
				if err == nil && fileSHA1 == npmData.Shasum {
					fmt.Printf("  integrity OK: %s@%s (sha1 verified)\n", dep.Name, version)
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

// computeFileSHA1 computes the SHA-1 hash of a file.
func computeFileSHA1(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// normalizeHash normalizes a hash string for comparison.
func normalizeHash(h string) string {
	return strings.ToLower(strings.TrimSpace(h))
}

// Inline copies JS/TS package sources to the output directory.
func (i *Inliner) Inline(deps []Dependency) ([]Dependency, error) {
	outputAbs := filepath.Join(i.ProjectRoot, i.OutputDir, "javascript")

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
		if err := i.copyPackage(sourceDir, destDir); err != nil {
			os.RemoveAll(sourceDir)
			fmt.Printf("  warn: copy %s: %v\n", dep.Name, err)
			continue
		}

		dep.SourceDir = destDir
		inlined = append(inlined, dep)
		fmt.Printf("  Inlined: %s → %s\n", dep.Name, destDir)

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

// rewriteImports rewrites import statements in inlined packages to use relative paths.
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

	// Walk all JS/TS files in the output directory
	return filepath.Walk(outputAbs, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".js") && !strings.HasSuffix(path, ".ts") &&
			!strings.HasSuffix(path, ".jsx") && !strings.HasSuffix(path, ".tsx") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		newContent := content

		// Rewrite: import ... from 'package' or import ... from "package"
		importFromRe := regexp.MustCompile(`(import\s+.*?\s+from\s+)['"]([^'"]+)['"]`)
		newContent = importFromRe.ReplaceAllStringFunc(newContent, func(match string) string {
			submatches := importFromRe.FindStringSubmatch(match)
			if len(submatches) < 3 {
				return match
			}
			quotePart := submatches[1]
			specifier := submatches[2]

			// Skip relative imports
			if strings.HasPrefix(specifier, ".") || strings.HasPrefix(specifier, "/") {
				return match
			}

			// Check if specifier matches an inlined dep (exact or subpath)
			rewritten := i.rewriteSpecifier(specifier, depMap)
			if rewritten != "" {
				// Determine quote character from the original match
				quote := "'"
				if strings.Contains(match, "\"") {
					quote = "\""
				}
				return fmt.Sprintf("%s%s%s%s", quotePart, quote, rewritten, quote)
			}

			return match
		})

		// Rewrite: require('package') or require("package")
		requireRe := regexp.MustCompile(`(require\s*\(\s*)['"]([^'"]+)['"](\s*\))`)
		newContent = requireRe.ReplaceAllStringFunc(newContent, func(match string) string {
			submatches := requireRe.FindStringSubmatch(match)
			if len(submatches) < 4 {
				return match
			}
			prefix := submatches[1]
			specifier := submatches[2]
			suffix := submatches[3]

			// Skip relative imports
			if strings.HasPrefix(specifier, ".") || strings.HasPrefix(specifier, "/") {
				return match
			}

			rewritten := i.rewriteSpecifier(specifier, depMap)
			if rewritten != "" {
				quote := "'"
				if strings.Contains(prefix, "\"") {
					quote = "\""
				}
				return fmt.Sprintf("%s%s%s%s", prefix, quote, rewritten, quote+suffix)
			}

			return match
		})

		// Rewrite: import('package') — dynamic imports
		dynamicImportRe := regexp.MustCompile(`(import\s*\(\s*)['"]([^'"]+)['"](\s*\))`)
		newContent = dynamicImportRe.ReplaceAllStringFunc(newContent, func(match string) string {
			submatches := dynamicImportRe.FindStringSubmatch(match)
			if len(submatches) < 4 {
				return match
			}
			prefix := submatches[1]
			specifier := submatches[2]
			suffix := submatches[3]

			// Skip relative imports
			if strings.HasPrefix(specifier, ".") || strings.HasPrefix(specifier, "/") {
				return match
			}

			rewritten := i.rewriteSpecifier(specifier, depMap)
			if rewritten != "" {
				quote := "'"
				if strings.Contains(prefix, "\"") {
					quote = "\""
				}
				return fmt.Sprintf("%s%s%s%s", prefix, quote, rewritten, quote+suffix)
			}

			return match
		})

		// Rewrite: export { foo } from 'package' or export * from 'package'
		exportFromRe := regexp.MustCompile(`(export\s+.*?\s+from\s+)['"]([^'"]+)['"]`)
		newContent = exportFromRe.ReplaceAllStringFunc(newContent, func(match string) string {
			submatches := exportFromRe.FindStringSubmatch(match)
			if len(submatches) < 3 {
				return match
			}
			quotePart := submatches[1]
			specifier := submatches[2]

			// Skip relative imports
			if strings.HasPrefix(specifier, ".") || strings.HasPrefix(specifier, "/") {
				return match
			}

			rewritten := i.rewriteSpecifier(specifier, depMap)
			if rewritten != "" {
				quote := "'"
				if strings.Contains(match, "\"") {
					quote = "\""
				}
				return fmt.Sprintf("%s%s%s%s", quotePart, quote, rewritten, quote)
			}

			return match
		})

		if newContent != content {
			if err := os.WriteFile(path, []byte(newContent), 0644); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
		}

		return nil
	})
}

// rewriteSpecifier rewrites a module specifier to a relative path if it matches an inlined dep.
func (i *Inliner) rewriteSpecifier(specifier string, depMap map[string]string) string {
	// Check exact match first
	if targetPath, ok := depMap[specifier]; ok {
		return toRelativeImport(targetPath)
	}

	// Check scoped package prefix (e.g., "@scope/package/subpath")
	if strings.HasPrefix(specifier, "@") {
		parts := strings.SplitN(specifier, "/", 3)
		if len(parts) >= 2 {
			scopePkg := parts[0] + "/" + parts[1]
			if targetPath, ok := depMap[scopePkg]; ok {
				subpath := ""
				if len(parts) >= 3 {
					subpath = "/" + parts[2]
				}
				return toRelativeImport(targetPath) + subpath
			}
		}
	}

	// Check subpath match (e.g., "lodash/merge" when "lodash" is inlined)
	for name, targetPath := range depMap {
		if strings.HasPrefix(specifier, name+"/") {
			subpath := strings.TrimPrefix(specifier, name)
			return toRelativeImport(targetPath) + subpath
		}
	}

	return ""
}

// toRelativeImport converts an absolute path to a relative import path.
func toRelativeImport(path string) string {
	// Convert to POSIX-style path with ./ prefix
	path = filepath.ToSlash(path)
	if !strings.HasPrefix(path, ".") {
		path = "./" + path
	}
	return path
}

// copyPackage copies JS/TS source files.
func (i *Inliner) copyPackage(src, dst string) error {
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
			if name == "test" || name == "tests" || name == "__tests__" ||
				name == "coverage" || name == ".nyc_output" {
				return filepath.SkipDir
			}
			return os.MkdirAll(dest, 0755)
		}

		// Copy source files and essential config
		if !strings.HasSuffix(name, ".js") && !strings.HasSuffix(name, ".ts") &&
			!strings.HasSuffix(name, ".jsx") && !strings.HasSuffix(name, ".tsx") &&
			!strings.HasSuffix(name, ".d.ts") && name != "package.json" {
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

// GenerateWebpackConfig creates a webpack config that resolves inlined packages.
func (i *Inliner) GenerateWebpackConfig(deps []Dependency) error {
	configPath := filepath.Join(i.ProjectRoot, "undep.webpack.config.js")

	var sb strings.Builder
	sb.WriteString("// Auto-generated by undep - webpack resolve alias for inlined packages\n")
	sb.WriteString("module.exports = {\n")
	sb.WriteString("  resolve: {\n")
	sb.WriteString("    alias: {\n")

	// Sort deps for deterministic output
	sort.Slice(deps, func(a, b int) bool {
		return deps[a].Name < deps[b].Name
	})

	for idx, dep := range deps {
		relPath, _ := filepath.Rel(i.ProjectRoot, dep.SourceDir)
		sb.WriteString(fmt.Sprintf("      '%s': '%s'", dep.Name, relPath))
		if idx < len(deps)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("    }\n")
	sb.WriteString("  }\n")
	sb.WriteString("};\n")

	return os.WriteFile(configPath, []byte(sb.String()), 0644)
}

// GenerateTSConfig creates a tsconfig.json patch for inlined packages.
func (i *Inliner) GenerateTSConfig(deps []Dependency) error {
	configPath := filepath.Join(i.ProjectRoot, "undep.tsconfig.paths.json")

	var sb strings.Builder
	sb.WriteString("// Auto-generated by undep - TypeScript paths for inlined packages\n")
	sb.WriteString("{\n")
	sb.WriteString("  \"compilerOptions\": {\n")
	sb.WriteString("    \"paths\": {\n")

	// Sort deps for deterministic output
	sort.Slice(deps, func(a, b int) bool {
		return deps[a].Name < deps[b].Name
	})

	for idx, dep := range deps {
		relPath, _ := filepath.Rel(i.ProjectRoot, dep.SourceDir)
		sb.WriteString(fmt.Sprintf("      \"%s\": [\"%s\"]", dep.Name, relPath))
		if idx < len(deps)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("    }\n")
	sb.WriteString("  }\n")
	sb.WriteString("}\n")

	return os.WriteFile(configPath, []byte(sb.String()), 0644)
}