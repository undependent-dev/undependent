// Package spdx generates SPDX 2.3 BOM documents.
package spdx

import (
	"encoding/json"
	"fmt"
	"time"
)

// Component represents a dependency for SPDX output.
type Component struct {
	Name    string
	Version string
	License string
}

// SPDXDocument is the top-level SPDX 2.3 structure.
type SPDXDocument struct {
	SPDXID            string           `json:"SPDXID"`
	SPDXVersion       string           `json:"spdxVersion"`
	DataLicense       string           `json:"dataLicense"`
	Name              string           `json:"name"`
	DocumentNamespace string           `json:"documentNamespace"`
	CreationInfo      *CreationInfo    `json:"creationInfo"`
	Packages          []SPDXPackage    `json:"packages"`
}

// CreationInfo holds document creation metadata.
type CreationInfo struct {
	Created     string   `json:"created"`
	Creators    []string `json:"creators"`
	LicenseListVersion string `json:"licenseListVersion"`
}

// SPDXPackage represents a single package in the SPDX document.
type SPDXPackage struct {
	SPDXID                        string `json:"SPDXID"`
	Name                          string `json:"name"`
	Version                       string `json:"versionInfo"`
	DownloadLocation              string `json:"downloadLocation"`
	FilesAnalyzed                 bool   `json:"filesAnalyzed"`
	LicenseConcluded              string `json:"licenseConcluded"`
	LicenseDeclared               string `json:"licenseDeclared"`
	LicenseInfoFromFiles          []string `json:"licenseInfoFromFiles"`
	CopyrightText                 string `json:"copyrightText"`
	PackageSPDXConformanceLevel   string `json:"packageSPDXConformanceLevel"`
}

// GenerateBOM creates a complete SPDX 2.3 JSON document.
func GenerateBOM(projectName string, components []Component) string {
	doc := SPDXDocument{
		SPDXID:            "SPDXRef-DOCUMENT",
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		Name:              projectName,
		DocumentNamespace: fmt.Sprintf("https://spdx.org/spdx/docs/undep/%s", projectName),
		CreationInfo: &CreationInfo{
			Created:            time.Now().UTC().Format(time.RFC3339),
			Creators:           []string{"Tool: undep-1.0.0"},
			LicenseListVersion: "3.21",
		},
		Packages: make([]SPDXPackage, 0, len(components)),
	}

	for i, comp := range components {
		license := comp.License
		if license == "" || license == "Unknown" {
			license = "NOASSERTION"
		}
		doc.Packages = append(doc.Packages, SPDXPackage{
			SPDXID:                        fmt.Sprintf("SPDXRef-Package-%d", i),
			Name:                          comp.Name,
			Version:                       comp.Version,
			DownloadLocation:              "NOASSERTION",
			FilesAnalyzed:                 false,
			LicenseConcluded:              license,
			LicenseDeclared:               license,
			LicenseInfoFromFiles:          []string{license},
			CopyrightText:                 "NOASSERTION",
			PackageSPDXConformanceLevel:   "3.0",
		})
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to generate SPDX: %v"}`, err)
	}
	return string(data)
}