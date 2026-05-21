// Package license detects and tracks licenses for inlined modules.
package license

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LicenseInfo tracks license obligations for a module.
type LicenseInfo struct {
	Type    string   // "MIT", "Apache-2.0", "BSD-3-Clause", "Unknown"
	File    string   // path to LICENSE file
	Authors []string // copyright holders
	Viral   bool     // true for GPL-family
}

// Detector scans a module's source directory for license files.
type Detector struct{}

// NewDetector creates a new Detector.
func NewDetector() *Detector {
	return &Detector{}
}

// Detect scans a module directory and returns license information.
func (d *Detector) Detect(moduleDir string) LicenseInfo {
	info := LicenseInfo{Type: "Unknown"}

	// Look for common license file names
	licenseNames := []string{
		"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENSE-MIT",
		"COPYING", "COPYING.md", "COPYING.txt",
	}

	for _, name := range licenseNames {
		path := filepath.Join(moduleDir, name)
		if _, err := os.Stat(path); err == nil {
			info.File = path
			return d.parseLicenseFile(path)
		}
	}

	// Check subdirectories
	entries, _ := os.ReadDir(moduleDir)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		lower := strings.ToLower(entry.Name())
		if strings.Contains(lower, "license") || strings.Contains(lower, "copying") {
			path := filepath.Join(moduleDir, entry.Name())
			return d.parseLicenseFile(path)
		}
	}

	return info
}

// parseLicenseFile reads and classifies a license file.
// DetectProjectLicense scans the project root directory for a LICENSE file
// and returns the detected license type. Returns "MIT" as default if not found.
func DetectProjectLicense(dir string) string {
	licenseNames := []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"}
	for _, name := range licenseNames {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			lower := strings.ToLower(string(data))
			// AGPL/LGPL before GPL (substring overlap)
			if strings.Contains(lower, "agpl") || strings.Contains(lower, "affero") {
				return "AGPL"
			} else if strings.Contains(lower, "lgpl") || strings.Contains(lower, "lesser") {
				return "LGPL"
			} else if strings.Contains(lower, "gpl") || strings.Contains(lower, "gnu general public") {
				return "GPL"
			} else if strings.Contains(lower, "mit license") {
				return "MIT"
			} else if strings.Contains(lower, "apache license") && strings.Contains(lower, "version 2.0") {
				return "Apache-2.0"
			} else if strings.Contains(lower, "bsd 3-clause") || strings.Contains(lower, "redistribution and use") {
				return "BSD-3-Clause"
			} else if strings.Contains(lower, "bsd 2-clause") {
				return "BSD-2-Clause"
			} else if strings.Contains(lower, "mozilla public") {
				return "MPL-2.0"
			} else if strings.Contains(lower, "isc license") {
				return "ISC"
			}
		}
	}
	return "MIT" // default fallback
}

// IsViralCompatible returns true if a source license is compatible with the
// project's license. For AGPL projects, GPL/AGPL deps are fine. For MIT projects,
// GPL/AGPL deps are incompatible.
func IsViralCompatible(sourceLicense, projectLicense string) bool {
	src := normalizeLicense(sourceLicense)
	tgt := normalizeLicense(projectLicense)
	// Same license is always compatible
	if src == tgt {
		return true
	}
	// AGPL project accepts GPL and AGPL
	if tgt == "AGPL" && (src == "GPL" || src == "AGPL") {
		return true
	}
	// GPL project accepts GPL
	if tgt == "GPL" && src == "GPL" {
		return true
	}
	// Permissive projects (MIT, Apache, BSD) do NOT accept GPL/AGPL
	if (tgt == "MIT" || tgt == "Apache-2.0" || tgt == "BSD-3-Clause" || tgt == "BSD-2-Clause") &&
		(src == "GPL" || src == "AGPL") {
		return false
	}
	// Unknown — assume compatible to avoid false positives
	return true
}

// parseLicenseFile reads and classifies a license file.
func (d *Detector) parseLicenseFile(path string) LicenseInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return LicenseInfo{Type: "Unknown", File: path}
	}

	content := string(data)
	lower := strings.ToLower(content)

	info := LicenseInfo{File: path, Type: "Unknown"}

	// Classify license type — check AGPL/LGPL BEFORE GPL (they contain "gpl" substring)
	if strings.Contains(lower, "mit license") {
		info.Type = "MIT"
	} else if strings.Contains(lower, "apache license") && strings.Contains(lower, "version 2.0") {
		info.Type = "Apache-2.0"
	} else if strings.Contains(lower, "bsd 3-clause") || strings.Contains(lower, "redistribution and use") {
		info.Type = "BSD-3-Clause"
	} else if strings.Contains(lower, "bsd 2-clause") {
		info.Type = "BSD-2-Clause"
	} else if strings.Contains(lower, "agpl") || strings.Contains(lower, "affero") {
		info.Type = "AGPL"
		info.Viral = true
	} else if strings.Contains(lower, "lgpl") || strings.Contains(lower, "lesser") {
		info.Type = "LGPL"
		info.Viral = true
	} else if strings.Contains(lower, "gpl") || strings.Contains(lower, "gnu general public") {
		info.Type = "GPL"
		info.Viral = true
	} else if strings.Contains(lower, "mozilla public") {
		info.Type = "MPL-2.0"
	} else if strings.Contains(lower, "isc license") {
		info.Type = "ISC"
	} else if strings.Contains(lower, "unlicense") || strings.Contains(lower, "public domain") {
		info.Type = "Public Domain"
	}

	// Extract copyright holders
	info.Authors = d.extractAuthors(content)

	return info
}

// extractAuthors tries to find copyright holders in the license text.
func (d *Detector) extractAuthors(content string) []string {
	var authors []string
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := scanner.Text()
		lower := strings.ToLower(line)

		if strings.Contains(lower, "copyright") {
			// Extract the part after "Copyright"
			idx := strings.Index(line, "Copyright")
			if idx >= 0 {
				author := strings.TrimSpace(line[idx+len("Copyright"):])
				author = strings.TrimPrefix(author, ":")
				author = strings.TrimSpace(author)
				if author != "" {
					authors = append(authors, author)
				}
			}
		}
	}

	if len(authors) == 0 {
		return []string{"Unknown"}
	}

	return authors
}

// ManifestEntry is a single entry in the license manifest.
type ManifestEntry struct {
	Path string
	Info LicenseInfo
}

// Manifest generates a LICENSE.absorbed file content.
func Manifest(entries []ManifestEntry, projectLicense string) string {
	var sb strings.Builder

	sb.WriteString("// LICENSE.absorbed\n")
	sb.WriteString("//\n")
	sb.WriteString("// This file was auto-generated by undep.\n")
	sb.WriteString("// It lists all licenses for inlined dependencies.\n")
	sb.WriteString("//\n\n")

	for _, e := range entries {
		sb.WriteString(fmt.Sprintf("Module: %s\n", e.Path))
		sb.WriteString(fmt.Sprintf("License: %s\n", e.Info.Type))
		if e.Info.File != "" {
			sb.WriteString(fmt.Sprintf("Source: %s\n", e.Info.File))
		}
		if len(e.Info.Authors) > 0 {
			sb.WriteString(fmt.Sprintf("Authors: %s\n", strings.Join(e.Info.Authors, ", ")))
		}
		if e.Info.Viral && !IsViralCompatible(e.Info.Type, projectLicense) {
			sb.WriteString("WARNING: Viral license (GPL-family) — may conflict with project license.\n")
		}
		sb.WriteString("\n")
	}

	return sb.String()
}