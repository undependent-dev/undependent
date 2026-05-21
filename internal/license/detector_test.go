package license

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetect_MIT(t *testing.T) {
	tmpDir := createTempLicense(t, "MIT License\n\nCopyright (c) 2024 Test Author\n\nPermission is hereby granted, free of charge, to any person obtaining a copy...")
	defer os.RemoveAll(tmpDir)

	d := NewDetector()
	info := d.Detect(tmpDir)

	if info.Type != "MIT" {
		t.Errorf("expected MIT, got %q", info.Type)
	}
	if info.Viral {
		t.Error("MIT should not be viral")
	}
	if len(info.Authors) == 0 || info.Authors[0] == "Unknown" {
		t.Error("expected author to be extracted")
	}
}

func TestDetect_Apache2(t *testing.T) {
	tmpDir := createTempLicense(t, "Apache License\nVersion 2.0, January 2004\n\nCopyright 2024 Apache Foundation")
	defer os.RemoveAll(tmpDir)

	d := NewDetector()
	info := d.Detect(tmpDir)

	if info.Type != "Apache-2.0" {
		t.Errorf("expected Apache-2.0, got %q", info.Type)
	}
	if info.Viral {
		t.Error("Apache-2.0 should not be viral")
	}
}

func TestDetect_GPL(t *testing.T) {
	tmpDir := createTempLicense(t, "GNU GENERAL PUBLIC LICENSE\nVersion 3\n\nCopyright (C) 2024 Free Software Foundation")
	defer os.RemoveAll(tmpDir)

	d := NewDetector()
	info := d.Detect(tmpDir)

	if info.Type != "GPL" {
		t.Errorf("expected GPL, got %q", info.Type)
	}
	if !info.Viral {
		t.Error("GPL should be viral")
	}
}

func TestDetect_BSD3(t *testing.T) {
	tmpDir := createTempLicense(t, "BSD 3-Clause License\n\nRedistribution and use in source and binary forms...")
	defer os.RemoveAll(tmpDir)

	d := NewDetector()
	info := d.Detect(tmpDir)

	if info.Type != "BSD-3-Clause" {
		t.Errorf("expected BSD-3-Clause, got %q", info.Type)
	}
	if info.Viral {
		t.Error("BSD-3-Clause should not be viral")
	}
}

func TestDetect_AGPL(t *testing.T) {
	tmpDir := createTempLicense(t, "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3")
	defer os.RemoveAll(tmpDir)

	d := NewDetector()
	info := d.Detect(tmpDir)

	if info.Type != "AGPL" {
		t.Errorf("expected AGPL, got %q", info.Type)
	}
	if !info.Viral {
		t.Error("AGPL should be viral")
	}
}

func TestDetect_LGPL(t *testing.T) {
	tmpDir := createTempLicense(t, "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1")
	defer os.RemoveAll(tmpDir)

	d := NewDetector()
	info := d.Detect(tmpDir)

	if info.Type != "LGPL" {
		t.Errorf("expected LGPL, got %q", info.Type)
	}
	if !info.Viral {
		t.Error("LGPL should be viral")
	}
}

func TestDetect_MPL2(t *testing.T) {
	tmpDir := createTempLicense(t, "Mozilla Public License Version 2.0")
	defer os.RemoveAll(tmpDir)

	d := NewDetector()
	info := d.Detect(tmpDir)

	if info.Type != "MPL-2.0" {
		t.Errorf("expected MPL-2.0, got %q", info.Type)
	}
}

func TestDetect_ISC(t *testing.T) {
	tmpDir := createTempLicense(t, "ISC License\n\nPermission to use, copy, modify...")
	defer os.RemoveAll(tmpDir)

	d := NewDetector()
	info := d.Detect(tmpDir)

	if info.Type != "ISC" {
		t.Errorf("expected ISC, got %q", info.Type)
	}
}

func TestDetect_PublicDomain(t *testing.T) {
	tmpDir := createTempLicense(t, "This is free and unencumbered software released into the public domain.\nUnlicense")
	defer os.RemoveAll(tmpDir)

	d := NewDetector()
	info := d.Detect(tmpDir)

	if info.Type != "Public Domain" {
		t.Errorf("expected Public Domain, got %q", info.Type)
	}
}

func TestDetect_Unknown(t *testing.T) {
	tmpDir := createTempLicense(t, "Some custom license text with no recognizable patterns")
	defer os.RemoveAll(tmpDir)

	d := NewDetector()
	info := d.Detect(tmpDir)

	if info.Type != "Unknown" {
		t.Errorf("expected Unknown, got %q", info.Type)
	}
}

func TestDetect_NoLicenseFile(t *testing.T) {
	tmpDir := t.TempDir()
	// No LICENSE file created

	d := NewDetector()
	info := d.Detect(tmpDir)

	if info.Type != "Unknown" {
		t.Errorf("expected Unknown for missing license, got %q", info.Type)
	}
}

func TestManifest(t *testing.T) {
	entries := []ManifestEntry{
		{Path: "github.com/test/mit-pkg", Info: LicenseInfo{Type: "MIT", Authors: []string{"Test"}}},
		{Path: "github.com/test/gpl-pkg", Info: LicenseInfo{Type: "GPL", Viral: true, Authors: []string{"FSF"}}},
	}

	result := Manifest(entries, "MIT")
	if result == "" {
		t.Error("manifest should not be empty")
	}
	if !contains(result, "github.com/test/mit-pkg") {
		t.Error("manifest should contain MIT package")
	}
	if !contains(result, "WARNING: Viral license") {
		t.Error("manifest should contain viral warning for GPL")
	}
}

func createTempLicense(t *testing.T, content string) string {
	tmpDir, err := os.MkdirTemp("", "undep-license-test-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "LICENSE"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return tmpDir
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}