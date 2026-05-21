package inline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeModuleName_Short(t *testing.T) {
	i := &Inliner{}
	result := i.safeModuleName("github.com/gin-gonic/gin")
	if result != "github.com__gin-gonic__gin" {
		t.Errorf("expected 'github.com__gin-gonic__gin', got %q", result)
	}
}

func TestSafeModuleName_Long(t *testing.T) {
	i := &Inliner{}
	longPath := "github.com/very/long/module/path/that/exceeds/one/hundred/and/twenty/eight/characters/and/needs/to/be/truncated/with/a/hash/prefix/to/avoid/filesystem/limitations"
	result := i.safeModuleName(longPath)
	if len(result) > 128+8+2 {
		t.Errorf("expected truncated name <= 138 chars, got %d", len(result))
	}
	// Should start with hash prefix (8 hex chars)
	if len(result) < 10 {
		t.Error("result too short")
	}
}

func TestSafeModuleName_SpecialChars(t *testing.T) {
	i := &Inliner{}
	result := i.safeModuleName("github.com/user/project-name_v2.0")
	if result == "" {
		t.Error("result should not be empty")
	}
	// Should not contain /
	if contains(result, "/") {
		t.Errorf("result should not contain /, got %q", result)
	}
}

func TestSafeModuleName_Deterministic(t *testing.T) {
	i := &Inliner{}
	path := "github.com/test/module"
	r1 := i.safeModuleName(path)
	r2 := i.safeModuleName(path)
	if r1 != r2 {
		t.Errorf("safeModuleName not deterministic: %q vs %q", r1, r2)
	}
}

func TestGenerateGoModReplacement(t *testing.T) {
	i := &Inliner{}

	directives := []string{
		"\tgithub.com/gin-gonic/gin v1.9.1 => ./internal/absorbed/github.com__gin-gonic__gin",
		"\tgithub.com/go-sql-driver/mysql v1.7.1 => ./internal/absorbed/github.com__go-sql-driver__mysql",
	}

	result := i.GenerateGoModReplacement(directives)
	if !contains(result, "replace (") {
		t.Error("should contain 'replace ('")
	}
	if !contains(result, "github.com/gin-gonic/gin") {
		t.Error("should contain gin module")
	}
	if !contains(result, "github.com/go-sql-driver/mysql") {
		t.Error("should contain mysql module")
	}
}

func TestGenerateGoModReplacement_Empty(t *testing.T) {
	i := &Inliner{}
	result := i.GenerateGoModReplacement(nil)
	if result != "" {
		t.Errorf("expected empty string for nil directives, got %q", result)
	}
}

func TestCopyModule(t *testing.T) {
	tmpDir := t.TempDir()

	// Create source structure
	srcDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "helper.go"), []byte("package sub"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	// Test file should be skipped
	if err := os.WriteFile(filepath.Join(srcDir, "main_test.go"), []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}

	dstDir := filepath.Join(tmpDir, "dst")
	i := &Inliner{}
	if err := i.copyModule(srcDir, dstDir); err != nil {
		t.Fatalf("copyModule failed: %v", err)
	}

	// Verify .go files were copied
	if _, err := os.Stat(filepath.Join(dstDir, "main.go")); os.IsNotExist(err) {
		t.Error("main.go should exist in destination")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "sub", "helper.go")); os.IsNotExist(err) {
		t.Error("sub/helper.go should exist in destination")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "data.json")); os.IsNotExist(err) {
		t.Error("data.json should exist in destination")
	}
	// Test file should NOT be copied
	if _, err := os.Stat(filepath.Join(dstDir, "main_test.go")); err == nil {
		t.Error("_test.go files should not be copied")
	}
}

func TestCopyFile(t *testing.T) {
	tmpDir := t.TempDir()

	src := filepath.Join(tmpDir, "src.txt")
	dst := filepath.Join(tmpDir, "sub", "dst.txt")
	expected := "hello world"

	if err := os.WriteFile(src, []byte(expected), 0644); err != nil {
		t.Fatal(err)
	}

	i := &Inliner{}
	if err := i.copyFile(src, dst); err != nil {
		t.Fatalf("copyFile failed: %v", err)
	}

	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst failed: %v", err)
	}
	if string(data) != expected {
		t.Errorf("expected %q, got %q", expected, string(data))
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}