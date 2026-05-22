// Package main is the CLI entry point for Undependent.
//
// Usage:
//
//	undependent scan    — Scan a Go project for third-party dependencies
//	undependent inline  — Inline (absorb) dependencies into your codebase
//	undependent verify  — Verify integrity of inlined dependencies
//	undependent report  — Generate a PDF security report
//	undependent init    — Initialize undep.yaml config in current project
//	undependent version — Print version info
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/undep/undep/internal/analyze"
	"github.com/undep/undep/internal/config"
	"github.com/undep/undep/internal/graph"
	"github.com/undep/undep/internal/inline"
	"github.com/undep/undep/internal/jsts"
	"github.com/undep/undep/internal/license"
	"github.com/undep/undep/internal/report"
	"github.com/undep/undep/pkg/types"
)

const version = "v1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(os.Args[2:])
	case "inline":
		err = cmdInline(os.Args[2:])
	case "absorb":
		err = cmdInline(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "init":
		err = cmdInit(os.Args[2:])
	case "version":
		fmt.Printf("undependent %s\n", version)
		return
	case "help", "--help", "-h":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Undependent — Be Undependent. Own Your Code.

Eliminate supply chain risk by absorbing third-party dependencies
into your codebase. No external registries. No upstream compromise.

Usage:
  undependent <command> [arguments]

Commands:
  scan [path]       Scan a Go project for third-party dependency usage
  inline [path]     Inline (absorb) dependencies into your codebase
  absorb [path]     Alias for inline
  verify [path]     Verify integrity of inlined dependencies against go.sum
  report [path]     Generate a PDF security assessment report
  init [path]       Initialize undep.yaml config in current project
  version           Print version information
  help              Show this help message

Examples:
  undependent scan .                    Scan current directory
  undependent scan /path/to/project     Scan specific project
  undependent inline .                  Inline all dependencies
  undependent verify .                  Verify inlined code integrity
  undependent report . --output report.pdf   Generate PDF report
  undependent init                      Create default config

For more info: https://undependent.dev`)
}

func cmdScan(args []string) error {
	targetDir, outputFlags := parseArgs(args)
	targetDir = resolveDir(targetDir)

	cfgPath, cfgErr := config.FindConfig(targetDir)
	if cfgErr != nil {
		cfgPath = ""
	}

	modulePath, err := discoverModule(targetDir)
	if err != nil {
		return fmt.Errorf("discover module: %w", err)
	}

	fmt.Printf("Scanning: %s\n", targetDir)
	fmt.Printf("Module:   %s\n", modulePath)
	if cfgPath != "" {
		fmt.Printf("Config:   %s\n", cfgPath)
	}
	fmt.Println()

	fmt.Println("Phase 1: Scanning for external symbol usage...")
	analyzer := analyze.NewAnalyzer(targetDir, modulePath)
	usages, err := analyzer.Scan()
	if err != nil {
		return fmt.Errorf("scan symbols: %w", err)
	}
	fmt.Printf("  Found %d external symbol usages\n", len(usages))

	fmt.Println("\nPhase 2: Resolving transitive dependencies...")
	resolver := analyze.NewTransitiveResolver(modulePath, targetDir)

	if cfgPath != "" {
		if c, err := config.Load(cfgPath); err == nil {
			resolver.MaxDepth = c.Inline.MaxDepth
			resolver.SkipCGO = c.Inline.SkipCGO
			if len(c.Inline.Allow) > 0 {
				for _, a := range c.Inline.Allow {
					resolver.AllowList[a] = true
				}
			}
			for _, d := range c.Inline.Deny {
				resolver.DenyList[d] = true
			}
		}
	}

	modules, err := resolver.Resolve(usages)
	if err != nil {
		return fmt.Errorf("resolve transitive deps: %w", err)
	}
	fmt.Printf("  %d modules need inlining (depth ≤ %d)\n", len(modules), resolver.MaxDepth)

	fmt.Println("\nPhase 3: Building dependency graph...")
	graphResolver := graph.NewResolver(targetDir)
	depGraph, err := graphResolver.Resolve()
	if err != nil {
		fmt.Printf("  Warning: graph resolution failed: %v\n", err)
		depGraph = &types.DepGraph{
			Nodes: make(map[string]*types.ModuleNode),
			ByPkg: make(map[string]*types.PkgNode),
		}
	}
	fmt.Printf("  %d modules in dependency graph\n", len(depGraph.Nodes))

	fmt.Println("\nPhase 4: Detecting licenses...")
	detector := license.NewDetector()
	var licenseInfos []license.LicenseInfo
	for path := range depGraph.Nodes {
		node := depGraph.Nodes[path]
		if node.SourceDir != "" {
			lr := detector.Detect(node.SourceDir)
			if lr.Type != "" && lr.Type != "Unknown" {
				licenseInfos = append(licenseInfos, lr)
				viral := "  "
				if lr.Viral {
					viral = "  [VIRAL]"
				}
				fmt.Printf("  %-50s %s%s\n", path, lr.Type, viral)
			}
		}
	}

	jsScanPath := filepath.Join(targetDir, "package.json")
	if _, err := os.Stat(jsScanPath); err == nil {
		fmt.Println("\nPhase 5: Scanning JavaScript/TypeScript dependencies...")
		jsInliner := jsts.NewInliner(targetDir, "")
		jsDeps, err := jsInliner.ResolveDependencies()
		if err != nil {
			fmt.Printf("  Warning: JS scan failed: %v\n", err)
		} else {
			fmt.Printf("  Found %d JavaScript/TypeScript dependencies\n", len(jsDeps))
			for _, dep := range jsDeps {
				fmt.Printf("  %-50s %s\n", dep.Name, dep.Version)
			}
		}
	}

	fmt.Println("\n─────────────────────────────────────────────")
	fmt.Printf("SCAN SUMMARY\n")
	fmt.Printf("  Module:              %s\n", modulePath)
	fmt.Printf("  External symbols:    %d\n", len(usages))
	fmt.Printf("  Modules to inline:   %d\n", len(modules))
	fmt.Printf("  Total deps:          %d\n", len(depGraph.Nodes))
	fmt.Printf("  Licenses detected:   %d\n", len(licenseInfos))

	viralCount := 0
	for _, lr := range licenseInfos {
		if lr.Viral {
			viralCount++
		}
	}
	if viralCount > 0 {
		fmt.Printf("  Viral licenses:      %d\n", viralCount)
	}
	fmt.Println("─────────────────────────────────────────────")

	for _, f := range outputFlags {
		if strings.HasPrefix(f, "--json=") {
			jsonPath := strings.TrimPrefix(f, "--json=")
			result := map[string]interface{}{
				"module":            modulePath,
				"external_symbols":  len(usages),
				"modules_to_inline": len(modules),
				"total_deps":        len(depGraph.Nodes),
				"licenses":          licenseInfos,
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			if err := os.WriteFile(jsonPath, data, 0644); err != nil {
				return fmt.Errorf("write JSON output: %w", err)
			}
			fmt.Printf("\nJSON report written to: %s\n", jsonPath)
		}
	}

	return nil
}

func cmdInline(args []string) error {
	targetDir, outputFlags := parseArgs(args)
	targetDir = resolveDir(targetDir)

	modulePath, err := discoverModule(targetDir)
	if err != nil {
		return fmt.Errorf("discover module: %w", err)
	}

	cfgPath, cfgErr := config.FindConfig(targetDir)
	if cfgErr != nil {
		fmt.Printf("No undep.yaml found. Creating default config...\n")
		cfgPath = filepath.Join(targetDir, "undep.yaml")
		if err := config.GenerateDefault(cfgPath, modulePath); err != nil {
			return fmt.Errorf("generate config: %w", err)
		}
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	outputDir := cfg.Project.OutputDir
	if outputDir == "" {
		outputDir = "internal/absorbed"
	}

	fmt.Printf("Inlining dependencies for: %s\n", modulePath)
	fmt.Printf("Output directory:          %s\n", outputDir)
	fmt.Println()

	fmt.Println("Phase 1: Scanning symbol usage...")
	analyzer := analyze.NewAnalyzer(targetDir, modulePath)
	usages, err := analyzer.Scan()
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	fmt.Println("Phase 2: Resolving transitive dependencies...")
	resolver := analyze.NewTransitiveResolver(modulePath, targetDir)
	resolver.MaxDepth = cfg.Inline.MaxDepth
	resolver.SkipCGO = cfg.Inline.SkipCGO
	for _, a := range cfg.Inline.Allow {
		resolver.AllowList[a] = true
	}
	for _, d := range cfg.Inline.Deny {
		resolver.DenyList[d] = true
	}

	modules, err := resolver.Resolve(usages)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}

	fmt.Println("Phase 3: Resolving module sources...")
	var moduleSources []inline.ModuleSource
	for _, modPath := range modules {
		sourceDir, err := inline.GetModuleSourceDir(targetDir, modPath)
		if err != nil {
			fmt.Printf("  Warning: could not find source for %s: %v\n", modPath, err)
			continue
		}

		v := ""
		if vv, ok := resolver.AllModules[modPath]; ok {
			v = vv
		}

		moduleSources = append(moduleSources, inline.ModuleSource{
			Path:      modPath,
			Version:   v,
			SourceDir: sourceDir,
		})
	}

	fmt.Println("Phase 4: Copying sources...")
	inliner := inline.NewInliner(targetDir, outputDir, modulePath)
	directives, err := inliner.Inline(moduleSources)
	if err != nil {
		return fmt.Errorf("inline: %w", err)
	}

	fmt.Println("Phase 5: Updating go.mod...")
	replaceBlock := inliner.GenerateGoModReplacement(directives)
	if replaceBlock != "" {
		goModPath := filepath.Join(targetDir, "go.mod")
		existing, err := os.ReadFile(goModPath)
		if err != nil {
			return fmt.Errorf("read go.mod: %w", err)
		}

		cleaned := removeReplaceBlock(string(existing))
		cleaned += replaceBlock

		if err := os.WriteFile(goModPath, []byte(cleaned), 0644); err != nil {
			return fmt.Errorf("write go.mod: %w", err)
		}
		fmt.Printf("  Added %d replace directives to go.mod\n", len(directives))
	}

	if cfg.License.Track {
		fmt.Println("Phase 6: Generating license manifest...")
		manifestPath := filepath.Join(targetDir, cfg.License.OutputFile)
		manifest, err := generateLicenseManifest(targetDir, modules)
		if err == nil {
			if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
				fmt.Printf("  Warning: could not write license manifest: %v\n", err)
			} else {
				fmt.Printf("  License manifest written to: %s\n", cfg.License.OutputFile)
			}
		}
	}

	fmt.Println("\n─────────────────────────────────────────────")
	fmt.Printf("INLINE COMPLETE\n")
	fmt.Printf("  Modules inlined:      %d\n", len(moduleSources))
	fmt.Printf("  Replace directives:   %d\n", len(directives))
	fmt.Printf("  Output:               %s\n", outputDir)
	fmt.Println("─────────────────────────────────────────────")
	fmt.Println("\nRun 'go mod tidy' to clean up, then 'go build' to verify.")

	for _, f := range outputFlags {
		if strings.HasPrefix(f, "--json=") {
			jsonPath := strings.TrimPrefix(f, "--json=")
			result := map[string]interface{}{
				"modules_inlined":    len(moduleSources),
				"replace_directives": len(directives),
				"output_dir":         outputDir,
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			os.WriteFile(jsonPath, data, 0644)
			fmt.Printf("\nJSON report written to: %s\n", jsonPath)
		}
	}

	return nil
}

func cmdVerify(args []string) error {
	targetDir, outputFlags := parseArgs(args)
	targetDir = resolveDir(targetDir)

	modulePath, err := discoverModule(targetDir)
	if err != nil {
		return fmt.Errorf("discover module: %w", err)
	}

	fmt.Printf("Verifying inlined dependencies for: %s\n", modulePath)
	fmt.Println()

	absorbedDir := filepath.Join(targetDir, "internal/absorbed")
	if _, err := os.Stat(absorbedDir); os.IsNotExist(err) {
		fmt.Println("No inlined dependencies found (internal/absorbed does not exist).")
		fmt.Println("Run 'undependent inline' first.")
		return nil
	}

	fmt.Println("Phase 1: Verifying replace directives...")
	goModContent, err := os.ReadFile(filepath.Join(targetDir, "go.mod"))
	if err != nil {
		return fmt.Errorf("read go.mod: %w", err)
	}

	replacePaths := extractReplacePaths(string(goModContent))
	missing := 0
	for _, rp := range replacePaths {
		fullPath := filepath.Join(targetDir, rp)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			fmt.Printf("  MISSING: %s\n", rp)
			missing++
		} else {
			fmt.Printf("  OK: %s\n", rp)
		}
	}

	fmt.Println("\nPhase 2: Verifying module integrity...")
	ok := runGoModVerify(targetDir)
	if ok {
		fmt.Println("  OK: go mod verify passed")
	} else {
		fmt.Println("  FAIL: go mod verify failed")
	}

	fmt.Println("\nPhase 3: Verifying build...")
	ok = runGoBuild(targetDir)
	if ok {
		fmt.Println("  OK: go build succeeded")
	} else {
		fmt.Println("  FAIL: go build failed")
	}

	fmt.Println("\nPhase 4: Checking licenses...")
	manifestPath := filepath.Join(targetDir, "LICENSE.absorbed")
	if _, err := os.Stat(manifestPath); err == nil {
		manifest, _ := os.ReadFile(manifestPath)
		if strings.Contains(string(manifest), "GPL") || strings.Contains(string(manifest), "AGPL") {
			fmt.Println("  WARNING: Viral licenses detected")
			fmt.Printf("  See: %s\n", manifestPath)
		} else {
			fmt.Println("  OK: No viral licenses detected")
		}
	}

	fmt.Println("\n─────────────────────────────────────────────")
	if missing == 0 && ok {
		fmt.Println("VERIFICATION PASSED")
	} else {
		fmt.Println("VERIFICATION ISSUES FOUND")
	}
	fmt.Printf("  Missing replace targets: %d\n", missing)
	fmt.Println("─────────────────────────────────────────────")

	for _, f := range outputFlags {
		if strings.HasPrefix(f, "--json=") {
			jsonPath := strings.TrimPrefix(f, "--json=")
			result := map[string]interface{}{
				"passed":               missing == 0 && ok,
				"missing_replacements": missing,
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			os.WriteFile(jsonPath, data, 0644)
			fmt.Printf("\nJSON report written to: %s\n", jsonPath)
		}
	}

	if missing > 0 {
		return fmt.Errorf("%d replace targets missing", missing)
	}
	return nil
}

func cmdReport(args []string) error {
	targetDir, outputFlags := parseArgs(args)
	targetDir = resolveDir(targetDir)

	outputFile := ""
	for _, f := range outputFlags {
		if strings.HasPrefix(f, "--output=") || strings.HasPrefix(f, "-o=") {
			outputFile = strings.TrimPrefix(f, "--output=")
			outputFile = strings.TrimPrefix(outputFile, "-o=")
		}
	}
	if outputFile == "" {
		outputFile = "undependent-report.pdf"
	}

	modulePath, err := discoverModule(targetDir)
	if err != nil {
		return fmt.Errorf("discover module: %w", err)
	}

	fmt.Printf("Generating security report for: %s\n", modulePath)
	fmt.Println()

	fmt.Println("Building dependency graph...")
	graphResolver := graph.NewResolver(targetDir)
	depGraph, err := graphResolver.Resolve()
	if err != nil {
		return fmt.Errorf("resolve graph: %w", err)
	}

	fmt.Println("Detecting licenses...")
	detector := license.NewDetector()
	var licEnts []report.LicEnt
	for path, node := range depGraph.Nodes {
		if node.SourceDir != "" {
			lr := detector.Detect(node.SourceDir)
			if lr.Type != "" && lr.Type != "Unknown" {
				licEnts = append(licEnts, report.LicEnt{
					Module: path,
					Type:   lr.Type,
					Viral:  lr.Viral,
				})
				// Also update the node's license info
				node.License = types.LicenseInfo{
					Type:  lr.Type,
					Viral: lr.Viral,
				}
			}
		}
	}

	scanResult := report.ScanResult{
		RepoURL:      targetDir,
		Language:     "go",
		DepCount:     len(depGraph.Nodes),
		VulnCount:    0,
		RiskScore:    calculateRiskScore(len(depGraph.Nodes), licEnts),
		RiskLevel:    "",
		Dependencies: make([]report.DepEnt, 0, len(depGraph.Nodes)),
		Vulns:        []report.VulnEnt{},
		Licenses:     licEnts,
	}

	for path, node := range depGraph.Nodes {
		scanResult.Dependencies = append(scanResult.Dependencies, report.DepEnt{
			Name:    path,
			Version: node.Version,
			License: node.License.Type,
		})
	}

	scanResult.RiskLevel = riskLevelFromScore(scanResult.RiskScore)

	fmt.Println("Generating PDF report...")
	pdfBytes, err := report.GeneratePDF(scanResult)
	if err != nil {
		return fmt.Errorf("generate PDF: %w", err)
	}

	if err := os.WriteFile(outputFile, pdfBytes, 0644); err != nil {
		return fmt.Errorf("write PDF: %w", err)
	}

	fmt.Println("\n─────────────────────────────────────────────")
	fmt.Printf("REPORT GENERATED\n")
	fmt.Printf("  Dependencies:    %d\n", scanResult.DepCount)
	fmt.Printf("  Licenses:        %d\n", len(licEnts))
	fmt.Printf("  Risk Score:      %d/100 (%s)\n", scanResult.RiskScore, scanResult.RiskLevel)
	fmt.Printf("  Output:          %s\n", outputFile)
	fmt.Println("─────────────────────────────────────────────")

	return nil
}

func cmdInit(args []string) error {
	targetDir, _ := parseArgs(args)
	targetDir = resolveDir(targetDir)

	modulePath, err := discoverModule(targetDir)
	if err != nil {
		return fmt.Errorf("discover module: %w", err)
	}

	cfgPath := filepath.Join(targetDir, "undep.yaml")

	if _, err := os.Stat(cfgPath); err == nil {
		fmt.Printf("undep.yaml already exists at %s\n", cfgPath)
		fmt.Println("Edit it directly or remove it to regenerate.")
		return nil
	}

	if err := config.GenerateDefault(cfgPath, modulePath); err != nil {
		return fmt.Errorf("generate config: %w", err)
	}

	fmt.Printf("Created: %s\n", cfgPath)
	fmt.Println()
	fmt.Println("Default configuration:")
	fmt.Println("  - Max transitive depth: 3")
	fmt.Println("  - Skip CGO packages: true")
	fmt.Println("  - Skip test files: true")
	fmt.Println("  - Track licenses: true")
	fmt.Println("  - Deny viral licenses: true")
	fmt.Println()
	fmt.Println("Edit undep.yaml to customize, then run:")
	fmt.Println("  undependent inline")

	return nil
}

// ── Helpers ──

func parseArgs(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return ".", args
}

func resolveDir(dir string) string {
	if dir == "" || dir == "." {
		dir, _ = os.Getwd()
	}
	abs, err := filepath.Abs(dir)
	if err == nil {
		dir = abs
	}
	return dir
}

func discoverModule(dir string) (string, error) {
	goModPath := filepath.Join(dir, "go.mod")
	if data, err := os.ReadFile(goModPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "module ") {
				return strings.TrimSpace(line[7:]), nil
			}
		}
	}

	cmd := exec.Command("go", "list", "-m", "-f", "{{.Module.Path}}")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("no go.mod found and go list failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func removeReplaceBlock(content string) string {
	inReplace := false
	var result []string
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "replace (") {
			inReplace = true
			continue
		}
		if inReplace {
			if trimmed == ")" {
				inReplace = false
			}
			continue
		}
		if strings.HasPrefix(trimmed, "replace ") && !strings.HasPrefix(trimmed, "replace (") {
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

func extractReplacePaths(content string) []string {
	var paths []string
	inReplace := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "replace (") {
			inReplace = true
			continue
		}
		if inReplace {
			if trimmed == ")" {
				break
			}
			parts := strings.Split(trimmed, "=>")
			if len(parts) == 2 {
				local := strings.TrimSpace(parts[1])
				paths = append(paths, local)
			}
		}
		if strings.HasPrefix(trimmed, "replace ") && !strings.HasPrefix(trimmed, "replace (") {
			parts := strings.Split(trimmed, "=>")
			if len(parts) == 2 {
				local := strings.TrimSpace(parts[1])
				paths = append(paths, local)
			}
		}
	}
	return paths
}

func generateLicenseManifest(targetDir string, modules []string) (string, error) {
	var sb strings.Builder
	sb.WriteString("// LICENSE.absorbed — Auto-generated license manifest\n")
	sb.WriteString("// Generated by Undependent\n")
	sb.WriteString("//\n")
	sb.WriteString("// This file tracks the licenses of all absorbed dependencies.\n")
	sb.WriteString("// Review viral licenses (GPL/AGPL) for compliance.\n\n")

	detector := license.NewDetector()
	for _, modPath := range modules {
		sourceDir, err := inline.GetModuleSourceDir(targetDir, modPath)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s: Unknown\n", modPath))
			continue
		}
		lr := detector.Detect(sourceDir)
		viral := ""
		if lr.Viral {
			viral = " [VIRAL]"
		}
		sb.WriteString(fmt.Sprintf("%s: %s%s\n", modPath, lr.Type, viral))
	}

	return sb.String(), nil
}

func calculateRiskScore(depCount int, licenses []report.LicEnt) int {
	score := 0
	if depCount > 50 {
		score += 40
	} else if depCount > 20 {
		score += 25
	} else if depCount > 10 {
		score += 10
	}
	for _, l := range licenses {
		if l.Viral {
			score += 15
		} else {
			score += 2
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func riskLevelFromScore(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}

func runGoModVerify(dir string) bool {
	cmd := exec.Command("go", "mod", "verify")
	cmd.Dir = dir
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

func runGoBuild(dir string) bool {
	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = dir
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}