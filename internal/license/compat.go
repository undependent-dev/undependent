// Package license provides license compatibility checking.
package license

import (
	"fmt"
)

// CompatibilityResult describes the relationship between two licenses.
type CompatibilityResult struct {
	SourceLicense string // license of the inlined code
	TargetLicense string // license of your project
	Compatible    bool
	Message       string
}

// CheckCompatibility determines if inlined code under sourceLicense can be used
// in a project licensed under targetLicense.
func CheckCompatibility(sourceLicense, targetLicense string) CompatibilityResult {
	// Permissive licenses are compatible with everything
	permissive := map[string]bool{
		"MIT": true, "Apache-2.0": true, "BSD-2-Clause": true,
		"BSD-3-Clause": true, "ISC": true, "Public Domain": true,
	}

	// Weak copyleft — can be combined with most licenses if kept separate
	weakCopyleft := map[string]bool{
		"LGPL": true, "MPL-2.0": true,
	}

	// Strong copyleft — viral
	strongCopyleft := map[string]bool{
		"GPL": true, "AGPL": true,
	}

	src := normalizeLicense(sourceLicense)
	tgt := normalizeLicense(targetLicense)

	// Same license is always compatible
	if src == tgt {
		return CompatibilityResult{
			SourceLicense: sourceLicense, TargetLicense: targetLicense,
			Compatible: true, Message: "Same license",
		}
	}

	// Permissive source → anything is fine
	if permissive[src] {
		return CompatibilityResult{
			SourceLicense: sourceLicense, TargetLicense: targetLicense,
			Compatible: true, Message: fmt.Sprintf("%s is permissive — compatible with %s", sourceLicense, targetLicense),
		}
	}

	// Weak copyleft source
	if weakCopyleft[src] {
		if permissive[tgt] || weakCopyleft[tgt] {
			return CompatibilityResult{
				SourceLicense: sourceLicense, TargetLicense: targetLicense,
				Compatible: true, Message: fmt.Sprintf("%s (weak copyleft) compatible with %s if kept as separate module", sourceLicense, targetLicense),
			}
		}
		if strongCopyleft[tgt] {
			return CompatibilityResult{
				SourceLicense: sourceLicense, TargetLicense: targetLicense,
				Compatible: true, Message: fmt.Sprintf("%s compatible with %s (strong copyleft absorbs weak)", sourceLicense, targetLicense),
			}
		}
		return CompatibilityResult{
			SourceLicense: sourceLicense, TargetLicense: targetLicense,
			Compatible: false, Message: fmt.Sprintf("WARNING: %s (weak copyleft) may conflict with %s — review required", sourceLicense, targetLicense),
		}
	}

	// Strong copyleft source (GPL, AGPL)
	if strongCopyleft[src] {
		if src == tgt {
			return CompatibilityResult{
				SourceLicense: sourceLicense, TargetLicense: targetLicense,
				Compatible: true, Message: "Same license",
			}
		}
		// GPL → AGPL is OK (AGPL is a superset)
		if src == "GPL" && tgt == "AGPL" {
			return CompatibilityResult{
				SourceLicense: sourceLicense, TargetLicense: targetLicense,
				Compatible: true, Message: "GPL code can be used in AGPL project",
			}
		}
		// Strong copyleft source requires target to be same or more restrictive
		return CompatibilityResult{
			SourceLicense: sourceLicense, TargetLicense: targetLicense,
			Compatible: false, Message: fmt.Sprintf("VIOLATION: %s is viral — inlining into %s project would require relicensing your project under %s", sourceLicense, targetLicense, sourceLicense),
		}
	}

	// Unknown source license
	if src == "Unknown" {
		return CompatibilityResult{
			SourceLicense: sourceLicense, TargetLicense: targetLicense,
			Compatible: false, Message: fmt.Sprintf("UNKNOWN: Cannot determine compatibility — source license is unknown, target is %s", targetLicense),
		}
	}

	return CompatibilityResult{
		SourceLicense: sourceLicense, TargetLicense: targetLicense,
		Compatible: false, Message: fmt.Sprintf("UNKNOWN: No compatibility rule for %s → %s", sourceLicense, targetLicense),
	}
}

// CheckAll checks multiple inlined licenses against a project license.
func CheckAll(sourceLicenses []string, targetLicense string) []CompatibilityResult {
	results := make([]CompatibilityResult, 0, len(sourceLicenses))
	for _, src := range sourceLicenses {
		results = append(results, CheckCompatibility(src, targetLicense))
	}
	return results
}

func normalizeLicense(lic string) string {
	switch lic {
	case "GPL", "GPL-2.0", "GPL-3.0", "GNU General Public License":
		return "GPL"
	case "AGPL", "AGPL-3.0", "GNU Affero General Public License":
		return "AGPL"
	case "LGPL", "LGPL-2.1", "LGPL-3.0", "GNU Lesser General Public License":
		return "LGPL"
	case "MPL-2.0", "Mozilla Public License":
		return "MPL-2.0"
	case "MIT", "MIT License":
		return "MIT"
	case "Apache-2.0", "Apache License 2.0":
		return "Apache-2.0"
	case "BSD-2-Clause", "BSD 2-Clause":
		return "BSD-2-Clause"
	case "BSD-3-Clause", "BSD 3-Clause":
		return "BSD-3-Clause"
	case "ISC", "ISC License":
		return "ISC"
	case "Public Domain", "Unlicense":
		return "Public Domain"
	default:
		return lic
	}
}