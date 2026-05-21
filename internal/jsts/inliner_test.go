package jsts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"import React from 'react'", "react"},
		{`import React from "react"`, "react"},
		{"import { useState } from 'react'", "react"},
		{"import 'lodash'", "lodash"},
		{"import axios from 'axios'", "axios"},
		{"import './styles.css'", ""},       // relative import
		{"import '../utils'", ""},           // relative import
		{"import '/absolute/path'", ""},     // absolute import
		{"import('@scope/package')", ""},    // not a from clause
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractPackageName(tt.input)
			if result != tt.expected {
				t.Errorf("extractPackageName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractRequirePackage(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"const fs = require('fs')", "fs"},
		{`const path = require("path")`, "path"},
		{"const _ = require('lodash')", "lodash"},
		{"require('./local')", ""},    // relative
		{"require('/absolute')", ""},  // absolute
		{"const x = 5", ""},           // not a require
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractRequirePackage(tt.input)
			if result != tt.expected {
				t.Errorf("extractRequirePackage(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractDynamicImport(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"const mod = import('lodash')", "lodash"},
		{`const mod = import("react")`, "react"},
		{"import('./local')", ""},  // relative
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractDynamicImport(tt.input)
			if result != tt.expected {
				t.Errorf("extractDynamicImport(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractReExport(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"export { foo } from 'lodash'", "lodash"},
		{`export * from "react"`, "react"},
		{"export { default } from './local'", ""}, // relative
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractReExport(tt.input)
			if result != tt.expected {
				t.Errorf("extractReExport(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParsePackageJSONDeps(t *testing.T) {
	tmpDir := t.TempDir()
	content := `{
		"name": "test-pkg",
		"version": "1.0.0",
		"dependencies": {
			"lodash": "^4.17.21",
			"express": "^4.18.0"
		},
		"peerDependencies": {
			"react": "^18.0.0"
		},
		"devDependencies": {
			"jest": "^29.0.0"
		}
	}`

	pkgPath := filepath.Join(tmpDir, "package.json")
	if err := os.WriteFile(pkgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	i := &Inliner{}
	deps := i.parsePackageJSONDeps(tmpDir)

	// Should have dependencies + peerDependencies (not devDependencies)
	if len(deps) != 3 {
		t.Errorf("expected 3 deps (dependencies + peerDependencies), got %d", len(deps))
	}

	depNames := make(map[string]bool)
	for _, d := range deps {
		depNames[d.Name] = true
	}
	for _, name := range []string{"lodash", "express", "react"} {
		if !depNames[name] {
			t.Errorf("missing dep %q", name)
		}
	}
}

func TestRewriteSpecifier(t *testing.T) {
	i := &Inliner{}
	depMap := map[string]string{
		"lodash":  "lodash",
		"express": "express",
		"@scope/pkg": "scope_pkg",
	}

	tests := []struct {
		specifier string
		expected  string
	}{
		{"lodash", "./lodash"},
		{"lodash/merge", "./lodash/merge"},
		{"express", "./express"},
		{"@scope/pkg", "./scope_pkg"},
		{"@scope/pkg/sub", "./scope_pkg/sub"},
		{"unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.specifier, func(t *testing.T) {
			result := i.rewriteSpecifier(tt.specifier, depMap)
			if result != tt.expected {
				t.Errorf("rewriteSpecifier(%q) = %q, want %q", tt.specifier, result, tt.expected)
			}
		})
	}
}