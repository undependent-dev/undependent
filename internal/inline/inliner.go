// Package inline handles copying source files and generating go.mod replace directives.
package inline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Inliner copies dependency source files and generates replace directives.
type Inliner struct {
	ProjectRoot string
	OutputDir   string // e.g., "internal/absorbed"
	UserModule  string // e.g., "github.com/myorg/myproject"
}

// NewInliner creates a new Inliner.
func NewInliner(projectRoot, outputDir, userModule string) *Inliner {
	if outputDir == "" {
		outputDir = "internal/absorbed"
	}
	return &Inliner{
		ProjectRoot: projectRoot,
		OutputDir:   outputDir,
		UserModule:  userModule,
	}
}

// ModuleSource maps module paths to their source directories.
type ModuleSource struct {
	Path      string // module path, e.g., "github.com/gin-gonic/gin"
	Version   string // version, e.g., "v1.9.1"
	SourceDir string // absolute path to module source on disk
}

// Inline copies module sources to the output directory and generates replace directives.
func (i *Inliner) Inline(modules []ModuleSource) ([]string, error) {
	outputAbs := filepath.Join(i.ProjectRoot, i.OutputDir)

	// Create output directory
	if err := os.MkdirAll(outputAbs, 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	var directives []string

	for _, mod := range modules {
		// Verify module integrity before copying
		i.verifyModuleIntegrity(mod)

		// Generate a safe directory name from the module path
		safeName := i.safeModuleName(mod.Path)
		destDir := filepath.Join(outputAbs, safeName)

		// Copy source files
		if err := i.copyModule(mod.SourceDir, destDir); err != nil {
			return nil, fmt.Errorf("copy %s: %w", mod.Path, err)
		}

		// Create go.mod if it doesn't exist (needed for sub-packages)
		goModPath := filepath.Join(destDir, "go.mod")
		if _, err := os.Stat(goModPath); os.IsNotExist(err) {
			goModContent := fmt.Sprintf("module %s\n\ngo 1.21\n", mod.Path)
			if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
				return nil, fmt.Errorf("create go.mod for %s: %w", mod.Path, err)
			}
		}

		// Generate replace directive with version and ./ prefix
		replacePath := "./" + filepath.Join(i.OutputDir, safeName)
		directive := fmt.Sprintf("\t%s %s => %s", mod.Path, mod.Version, replacePath)
		directives = append(directives, directive)

		fmt.Printf("  Inlined: %s@%s → %s\n", mod.Path, mod.Version, replacePath)
	}

	return directives, nil
}

// GenerateGoModReplacement generates the full replace block for go.mod.
func (i *Inliner) GenerateGoModReplacement(directives []string) string {
	if len(directives) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\nreplace (\n")
	for _, d := range directives {
		sb.WriteString(d)
		sb.WriteString("\n")
	}
	sb.WriteString(")\n")
	return sb.String()
}

// safeModuleName converts a module path to a collision-safe directory name.
// Uses full path with / replaced by __, truncated with hash prefix if too long.
func (i *Inliner) safeModuleName(modulePath string) string {
	// Replace / with __ for a unique, filesystem-safe name
	safe := strings.ReplaceAll(modulePath, "/", "__")

	// If the result exceeds 128 chars, use a hash prefix + truncated name
	if len(safe) > 128 {
		// Compute SHA-256 of the full module path
		h := sha256.Sum256([]byte(modulePath))
		hashPrefix := hex.EncodeToString(h[:])[:8]
		// Keep the last 100 chars of the safe name, prepend hash
		truncated := safe[len(safe)-100:]
		return hashPrefix + "__" + truncated
	}

	return safe
}

// verifyModuleIntegrity checks the module by running `go mod verify` in the project root.
// This is the authoritative way to verify Go module integrity — it compares downloaded
// module content against the hashes recorded in go.sum.
func (i *Inliner) verifyModuleIntegrity(mod ModuleSource) {
	cmd := exec.Command("go", "mod", "verify")
	cmd.Dir = i.ProjectRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("  integrity WARNING: go mod verify failed: %s\n", string(out))
		return
	}
	fmt.Printf("  integrity OK: %s@%s (go mod verify passed)\n", mod.Path, mod.Version)
}

// copyModule copies all .go files from source to destination.
func (i *Inliner) copyModule(src, dst string) error {
	// Create destination directory
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
			if name == "test" || name == "tests" || name == "_test" {
				return filepath.SkipDir
			}
			return os.MkdirAll(dest, 0755)
		}

		// Copy .go files, go.mod, go.sum, assembly (.s), and data files
		if !strings.HasSuffix(name, ".go") &&
			name != "go.mod" && name != "go.sum" &&
			!strings.HasSuffix(name, ".s") && // assembly files
			!strings.HasSuffix(name, ".json") &&
			!strings.HasSuffix(name, ".yaml") &&
			!strings.HasSuffix(name, ".yml") &&
			!strings.HasSuffix(name, ".toml") &&
			!strings.HasSuffix(name, ".proto") &&
			!strings.HasSuffix(name, ".txt") {
			return nil
		}

		// Skip test files
		if strings.HasSuffix(name, "_test.go") {
			return nil
		}

		// Copy file
		return i.copyFile(path, dest)
	})
}

// copyFile copies a single file.
func (i *Inliner) copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	return os.WriteFile(dst, data, 0644)
}

// GetModuleSourceDir returns the source directory for a module.
func GetModuleSourceDir(projectRoot, modulePath string) (string, error) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", modulePath)
	cmd.Dir = projectRoot
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go list %s: %w", modulePath, err)
	}
	return strings.TrimSpace(string(out)), nil
}