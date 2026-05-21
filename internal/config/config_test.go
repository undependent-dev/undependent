package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Project.OutputDir != "internal/absorbed" {
		t.Errorf("expected output_dir 'internal/absorbed', got %q", cfg.Project.OutputDir)
	}
	if cfg.Inline.MaxDepth != 3 {
		t.Errorf("expected max_depth 3, got %d", cfg.Inline.MaxDepth)
	}
	if !cfg.Inline.SkipCGO {
		t.Error("expected skip_cgo true")
	}
	if !cfg.Inline.SkipTestFiles {
		t.Error("expected skip_test_files true")
	}
	if !cfg.License.Track {
		t.Error("expected license track true")
	}
	if !cfg.License.DenyViral {
		t.Error("expected license deny_viral true")
	}
}

func TestParseYAML_FullConfig(t *testing.T) {
	yaml := `
project:
    module: github.com/myorg/myproject
    output_dir: vendor/absorbed

inline:
    max_depth: 5
    skip_cgo: false
    skip_test_files: false
    allow: [github.com/gin-gonic/gin, github.com/go-sql-driver/mysql]
    deny: [github.com/evil/kit]

license:
    track: false
    deny_viral: false
    output: licenses.txt
`
	cfg, err := parseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parseYAML failed: %v", err)
	}

	if cfg.Project.Module != "github.com/myorg/myproject" {
		t.Errorf("module: got %q", cfg.Project.Module)
	}
	if cfg.Project.OutputDir != "vendor/absorbed" {
		t.Errorf("output_dir: got %q", cfg.Project.OutputDir)
	}
	if cfg.Inline.MaxDepth != 5 {
		t.Errorf("max_depth: got %d", cfg.Inline.MaxDepth)
	}
	if cfg.Inline.SkipCGO {
		t.Error("skip_cgo should be false")
	}
	if cfg.Inline.SkipTestFiles {
		t.Error("skip_test_files should be false")
	}
	if len(cfg.Inline.Allow) != 2 {
		t.Errorf("allow: expected 2 entries, got %d", len(cfg.Inline.Allow))
	}
	if len(cfg.Inline.Deny) != 1 {
		t.Errorf("deny: expected 1 entry, got %d", len(cfg.Inline.Deny))
	}
	if cfg.License.Track {
		t.Error("license track should be false")
	}
	if cfg.License.OutputFile != "licenses.txt" {
		t.Errorf("output: got %q", cfg.License.OutputFile)
	}
}

func TestParseYAML_Minimal(t *testing.T) {
	yaml := `
project:
    module: github.com/test/test
`
	cfg, err := parseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parseYAML failed: %v", err)
	}
	if cfg.Project.Module != "github.com/test/test" {
		t.Errorf("module: got %q", cfg.Project.Module)
	}
	// Defaults should apply for missing fields
	if cfg.Inline.MaxDepth != 3 {
		t.Errorf("max_depth default: got %d", cfg.Inline.MaxDepth)
	}
}

func TestParseYAML_Empty(t *testing.T) {
	cfg, err := parseYAML([]byte(""))
	if err != nil {
		t.Fatalf("parseYAML failed on empty: %v", err)
	}
	// Should return defaults
	if cfg.Inline.MaxDepth != 3 {
		t.Errorf("empty config should use defaults, got max_depth %d", cfg.Inline.MaxDepth)
	}
}

func TestParseYAML_Comments(t *testing.T) {
	yaml := `
# This is a comment
project:
    module: github.com/test/test
    # output_dir uses default
`
	cfg, err := parseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parseYAML failed: %v", err)
	}
	if cfg.Project.Module != "github.com/test/test" {
		t.Errorf("module: got %q", cfg.Project.Module)
	}
}

func TestGenerateDefault(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "undep-config-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "undep.yaml")
	err = GenerateDefault(path, "github.com/test/project")
	if err != nil {
		t.Fatalf("GenerateDefault failed: %v", err)
	}

	// Verify file exists and can be parsed back
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Project.Module != "github.com/test/project" {
		t.Errorf("module: got %q", cfg.Project.Module)
	}
}

func TestFindConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "undep-find-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create config in a subdirectory
	subDir := filepath.Join(tmpDir, "sub", "deep")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(tmpDir, "undep.yaml")
	if err := os.WriteFile(configPath, []byte("project:\n    module: test\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// FindConfig should walk up and find it
	found, err := FindConfig(subDir)
	if err != nil {
		t.Fatalf("FindConfig failed: %v", err)
	}
	if found != configPath {
		t.Errorf("expected %s, got %s", configPath, found)
	}
}

func TestFindConfig_NotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "undep-find-empty-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	_, err = FindConfig(tmpDir)
	if err == nil {
		t.Error("expected error when no config found")
	}
}

func TestMarshalYAML_RoundTrip(t *testing.T) {
	cfg := &Config{
		Project: ProjectConfig{
			Module:    "github.com/test/roundtrip",
			OutputDir: "vendor/deps",
		},
		Inline: InlineConfig{
			MaxDepth:      4,
			SkipCGO:       false,
			SkipTestFiles: true,
			Allow:         []string{"a", "b"},
			Deny:          []string{"c"},
		},
		License: LicenseConfig{
			Track:      true,
			DenyViral:  false,
			OutputFile: "custom.txt",
		},
	}

	data, err := marshalYAML(cfg)
	if err != nil {
		t.Fatalf("marshalYAML failed: %v", err)
	}

	parsed, err := parseYAML(data)
	if err != nil {
		t.Fatalf("parseYAML of marshaled data failed: %v", err)
	}

	if parsed.Project.Module != cfg.Project.Module {
		t.Errorf("module round-trip: got %q", parsed.Project.Module)
	}
	if parsed.Inline.MaxDepth != cfg.Inline.MaxDepth {
		t.Errorf("max_depth round-trip: got %d", parsed.Inline.MaxDepth)
	}
	if len(parsed.Inline.Allow) != len(cfg.Inline.Allow) {
		t.Errorf("allow round-trip: got %d entries", len(parsed.Inline.Allow))
	}
}