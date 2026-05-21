package rust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractCrateName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"use serde::json::to_string", "serde"},
		{"use tokio::runtime::Runtime", "tokio"},
		{"extern crate serde;", "serde"},
		{"extern crate tokio;", "tokio"},
		{"use self::local", ""},
		{"use super::parent", ""},
		{"use crate::my_mod", ""},
		{"use std::io::Read", "std"}, // stdlib but still extracted
		{"let x = 5;", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractCrateName(tt.input)
			if result != tt.expected {
				t.Errorf("extractCrateName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseCargoSection(t *testing.T) {
	content := `[dependencies]
serde = "1.0"
tokio = { version = "1.28", features = ["full"] }
reqwest = "0.11"
local-crate = { path = "../local" }

[dev-dependencies]
criterion = "0.4"

[build-dependencies]
cc = "1.0"
`
	i := &Inliner{}

	// Parse [dependencies]
	deps := i.parseCargoSection(content, "[dependencies]")
	if len(deps) != 3 {
		t.Errorf("expected 3 runtime deps (path deps excluded), got %d", len(deps))
	}

	depNames := make(map[string]bool)
	for _, d := range deps {
		depNames[d.Name] = true
	}
	for _, name := range []string{"serde", "tokio", "reqwest"} {
		if !depNames[name] {
			t.Errorf("missing dep %q in [dependencies]", name)
		}
	}

	// Parse [dev-dependencies]
	devDeps := i.parseCargoSection(content, "[dev-dependencies]")
	if len(devDeps) != 1 {
		t.Errorf("expected 1 dev dep, got %d", len(devDeps))
	}
	if len(devDeps) > 0 && devDeps[0].Name != "criterion" {
		t.Errorf("expected criterion, got %q", devDeps[0].Name)
	}

	// Parse [build-dependencies]
	buildDeps := i.parseCargoSection(content, "[build-dependencies]")
	if len(buildDeps) != 1 {
		t.Errorf("expected 1 build dep, got %d", len(buildDeps))
	}
}

func TestParseCargoSection_QuotedVersions(t *testing.T) {
	content := `[dependencies]
serde = "1.0.160"
tokio = "^1.28.0"
`
	i := &Inliner{}
	deps := i.parseCargoSection(content, "[dependencies]")

	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}

	// Versions should have quotes stripped
	for _, d := range deps {
		if d.Version == "" {
			t.Errorf("dep %s has empty version", d.Name)
		}
	}
}

func TestGetIndent(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"    use foo;", "    "},
		{"\tuse foo;", "\t"},
		{"  \t  use foo;", "  \t  "},
		{"use foo;", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := getIndent(tt.input)
			if result != tt.expected {
				t.Errorf("getIndent(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestPrefixForCrate(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"a", "a"},
		{"ab", "ab"},
		{"abc", "abc"},
		{"serde", "ser"},
		{"tokio", "tok"},
		{"reqwest", "req"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := prefixForCrate(tt.name)
			if result != tt.expected {
				t.Errorf("prefixForCrate(%q) = %q, want %q", tt.name, result, tt.expected)
			}
		})
	}
}

func TestGenerateCargoConfig(t *testing.T) {
	tmpDir := t.TempDir()
	i := &Inliner{ProjectRoot: tmpDir}

	deps := []Dependency{
		{Name: "serde", Version: "1.0", SourceDir: filepath.Join(tmpDir, "internal/absorbed/rust/serde")},
		{Name: "tokio", Version: "1.28", SourceDir: filepath.Join(tmpDir, "internal/absorbed/rust/tokio")},
	}

	if err := i.GenerateCargoConfig(deps); err != nil {
		t.Fatalf("GenerateCargoConfig failed: %v", err)
	}

	configPath := filepath.Join(tmpDir, "undep.cargo.toml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config failed: %v", err)
	}

	content := string(data)
	if !contains(content, "[patch.crates-io]") {
		t.Error("should contain [patch.crates-io]")
	}
	if !contains(content, "serde = { path =") {
		t.Error("should contain serde patch")
	}
	if !contains(content, "tokio = { path =") {
		t.Error("should contain tokio patch")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s != "" && substr != ""
}