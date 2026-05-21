package python

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePythonDepString(t *testing.T) {
	tests := []struct {
		input    string
		wantName string
		wantVer  string
	}{
		{"requests>=2.28.0", "requests", ">=2.28.0"},
		{"flask==2.0.1", "flask", "==2.0.1"},
		{"numpy", "numpy", ""},
		{"pandas<=1.5.0", "pandas", "<=1.5.0"},
		{"scipy!=1.7.0", "scipy", "!=1.7.0"},
		{"  django>3.0  ", "django", ">3.0"},
		{"boto3<2.0", "boto3", "<2.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			dep := parsePythonDepString(tt.input)
			if dep.Name != tt.wantName {
				t.Errorf("name: got %q, want %q", dep.Name, tt.wantName)
			}
			if dep.Version != tt.wantVer {
				t.Errorf("version: got %q, want %q", dep.Version, tt.wantVer)
			}
		})
	}
}

func TestParseRequirements(t *testing.T) {
	tmpDir := t.TempDir()
	content := `# This is a comment
requests>=2.28.0
flask==2.0.1
numpy

# Another comment
pandas<=1.5.0
-e git+https://github.com/test/repo.git
`
	reqPath := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(reqPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	i := &Inliner{ProjectRoot: tmpDir}
	deps, err := i.parseRequirements(reqPath)
	if err != nil {
		t.Fatalf("parseRequirements failed: %v", err)
	}

	// Should have 4 deps (comments and -e lines skipped)
	if len(deps) != 4 {
		t.Errorf("expected 4 deps, got %d", len(deps))
	}

	depNames := make(map[string]bool)
	for _, d := range deps {
		depNames[d.Name] = true
	}
	for _, name := range []string{"requests", "flask", "numpy", "pandas"} {
		if !depNames[name] {
			t.Errorf("missing dep %q", name)
		}
	}
}

func TestParsePyprojectTOML_PEP621(t *testing.T) {
	tmpDir := t.TempDir()
	content := `[project]
name = "myproject"
version = "1.0.0"
dependencies = [
    "requests>=2.28.0",
    "flask==2.0.1",
    "numpy",
]

[build-system]
requires = ["setuptools"]
`
	path := filepath.Join(tmpDir, "pyproject.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	i := &Inliner{ProjectRoot: tmpDir}
	deps, err := i.parsePyprojectTOML(path)
	if err != nil {
		t.Fatalf("parsePyprojectTOML failed: %v", err)
	}

	if len(deps) != 3 {
		t.Errorf("expected 3 deps, got %d", len(deps))
	}
}

func TestParsePyprojectTOML_Poetry(t *testing.T) {
	tmpDir := t.TempDir()
	content := `[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28"
flask = ">=2.0"

[tool.poetry.dev-dependencies]
pytest = "^7.0"
`
	path := filepath.Join(tmpDir, "pyproject.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	i := &Inliner{ProjectRoot: tmpDir}
	deps, err := i.parsePyprojectTOML(path)
	if err != nil {
		t.Fatalf("parsePyprojectTOML failed: %v", err)
	}

	// Should have requests and flask (python is skipped)
	if len(deps) < 2 {
		t.Errorf("expected at least 2 deps, got %d", len(deps))
	}
}

func TestParseMetadataFile(t *testing.T) {
	tmpDir := t.TempDir()
	content := `Metadata-Version: 2.1
Name: test-package
Version: 1.0.0
Requires-Dist: requests>=2.28.0
Requires-Dist: flask==2.0.1
Requires-Dist: numpy[extra]>=1.21; python_version >= "3.7"
Summary: A test package
`
	path := filepath.Join(tmpDir, "METADATA")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	i := &Inliner{ProjectRoot: tmpDir}
	deps := i.parseMetadataFile(content)

	if len(deps) < 2 {
		t.Errorf("expected at least 2 deps, got %d", len(deps))
	}
}

func TestParseSetupPy(t *testing.T) {
	content := `from setuptools import setup

setup(
    name="test",
    version="1.0",
    install_requires=[
        "requests>=2.28.0",
        "flask==2.0.1",
        "numpy",
    ],
)
`
	i := &Inliner{}
	deps := i.parseSetupPy(content)

	if len(deps) != 3 {
		t.Errorf("expected 3 deps, got %d", len(deps))
	}
}