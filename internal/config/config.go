// Package config handles loading and validating undep configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config represents the full undep configuration.
type Config struct {
	Project ProjectConfig
	Inline  InlineConfig
	License LicenseConfig
}

// ProjectConfig contains project-level settings.
type ProjectConfig struct {
	Module    string // Go module path
	OutputDir string // where inlined code lives
}

// InlineConfig controls inlining behavior.
type InlineConfig struct {
	MaxDepth      int      // transitive resolution depth
	SkipCGO       bool     // skip packages with CGO
	SkipTestFiles bool     // don't inline _test.go
	Allow         []string // if set, ONLY these modules
	Deny          []string // never inline these
}

// LicenseConfig controls license tracking.
type LicenseConfig struct {
	Track      bool   // generate license manifest
	DenyViral  bool   // refuse to inline GPL code
	OutputFile string // manifest file path
}

// Defaults returns a Config with sensible defaults.
func Defaults() Config {
	return Config{
		Project: ProjectConfig{
			OutputDir: "internal/absorbed",
		},
		Inline: InlineConfig{
			MaxDepth:      3,
			SkipCGO:       true,
			SkipTestFiles: true,
		},
		License: LicenseConfig{
			Track:      true,
			DenyViral:  true,
			OutputFile: "LICENSE.absorbed",
		},
	}
}

// ─── Minimal YAML parser for our config subset ───

// parseKeyValue splits "key: value" handling quoted strings.
func parseKeyValue(line string) (string, string) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", line
	}
	key := strings.TrimSpace(line[:idx])
	val := strings.TrimSpace(line[idx+1:])
	// Strip quotes
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	return key, val
}

// parseValue converts a string value to the appropriate type.
func parseValue(raw string) interface{} {
	// Empty array
	if raw == "[]" {
		return []string{}
	}
	// Bracket array: [a, b, c]
	if len(raw) >= 2 && raw[0] == '[' && raw[len(raw)-1] == ']' {
		inner := strings.TrimSpace(raw[1 : len(raw)-1])
		if inner == "" {
			return []string{}
		}
		parts := strings.Split(inner, ",")
		var out []string
		for _, p := range parts {
			s := strings.TrimSpace(p)
			if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
				s = s[1 : len(s)-1]
			}
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	// Bool
	if raw == "true" {
		return true
	}
	if raw == "false" {
		return false
	}
	// Int
	if n, err := strconv.Atoi(raw); err == nil {
		return n
	}
	// String
	return raw
}

// parseYAML parses our simple 2-level YAML config.
func parseYAML(data []byte) (*Config, error) {
	cfg := Defaults()
	lines := strings.Split(string(data), "\n")

	var currentSection string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Top-level section (no leading whitespace)
		if len(line) > 0 && (line[0] != ' ' && line[0] != '\t') {
			if strings.HasSuffix(trimmed, ":") {
				currentSection = strings.TrimSuffix(trimmed, ":")
			}
			continue
		}

		// Nested key: value
		key, val := parseKeyValue(trimmed)
		if key == "" {
			continue
		}

		parsed := parseValue(val)

		switch currentSection {
		case "project":
			switch key {
			case "module":
				if s, ok := parsed.(string); ok {
					cfg.Project.Module = s
				}
			case "output_dir":
				if s, ok := parsed.(string); ok {
					cfg.Project.OutputDir = s
				}
			}
		case "inline":
			switch key {
			case "max_depth":
				if n, ok := parsed.(int); ok {
					cfg.Inline.MaxDepth = n
				}
			case "skip_cgo":
				if b, ok := parsed.(bool); ok {
					cfg.Inline.SkipCGO = b
				}
			case "skip_test_files":
				if b, ok := parsed.(bool); ok {
					cfg.Inline.SkipTestFiles = b
				}
			case "allow":
				if a, ok := parsed.([]string); ok {
					cfg.Inline.Allow = a
				}
			case "deny":
				if a, ok := parsed.([]string); ok {
					cfg.Inline.Deny = a
				}
			}
		case "license":
			switch key {
			case "track":
				if b, ok := parsed.(bool); ok {
					cfg.License.Track = b
				}
			case "deny_viral":
				if b, ok := parsed.(bool); ok {
					cfg.License.DenyViral = b
				}
			case "output":
				if s, ok := parsed.(string); ok {
					cfg.License.OutputFile = s
				}
			}
		}
	}

	return &cfg, nil
}

// formatValue converts a value back to YAML string.
func formatValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case int:
		return strconv.Itoa(val)
	case bool:
		return strconv.FormatBool(val)
	case []string:
		if len(val) == 0 {
			return "[]"
		}
		var parts []string
		for _, s := range val {
			parts = append(parts, s)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprintf("%v", v)
	}
}

// marshalYAML generates YAML for our config.
func marshalYAML(cfg *Config) ([]byte, error) {
	var b strings.Builder

	b.WriteString("project:\n")
	b.WriteString(fmt.Sprintf("    module: %s\n", formatValue(cfg.Project.Module)))
	b.WriteString(fmt.Sprintf("    output_dir: %s\n", formatValue(cfg.Project.OutputDir)))

	b.WriteString("inline:\n")
	b.WriteString(fmt.Sprintf("    max_depth: %s\n", formatValue(cfg.Inline.MaxDepth)))
	b.WriteString(fmt.Sprintf("    skip_cgo: %s\n", formatValue(cfg.Inline.SkipCGO)))
	b.WriteString(fmt.Sprintf("    skip_test_files: %s\n", formatValue(cfg.Inline.SkipTestFiles)))
	b.WriteString(fmt.Sprintf("    allow: %s\n", formatValue(cfg.Inline.Allow)))
	b.WriteString(fmt.Sprintf("    deny: %s\n", formatValue(cfg.Inline.Deny)))

	b.WriteString("license:\n")
	b.WriteString(fmt.Sprintf("    track: %s\n", formatValue(cfg.License.Track)))
	b.WriteString(fmt.Sprintf("    deny_viral: %s\n", formatValue(cfg.License.DenyViral)))
	b.WriteString(fmt.Sprintf("    output: %s\n", formatValue(cfg.License.OutputFile)))

	return []byte(b.String()), nil
}

// Load reads and parses the config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	return parseYAML(data)
}

// FindConfig searches for undep.yaml in the project root and parents.
func FindConfig(startDir string) (string, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", err
	}

	for {
		candidate := filepath.Join(dir, "undep.yaml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}

		// Also check for inliner.yaml (legacy name)
		candidate = filepath.Join(dir, "inliner.yaml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no undep.yaml found")
		}
		dir = parent
	}
}

// GenerateDefault creates a default undep.yaml file.
func GenerateDefault(path string, modulePath string) error {
	cfg := Defaults()
	cfg.Project.Module = modulePath

	data, err := marshalYAML(&cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}