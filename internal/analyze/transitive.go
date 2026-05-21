// Package analyze provides transitive dependency resolution via BFS.
package analyze

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
)

// TransitiveResolver performs BFS through the dependency graph to find
// all packages that need to be inlined.
type TransitiveResolver struct {
	MaxDepth    int
	SkipCGO     bool
	AllowList   map[string]bool
	DenyList    map[string]bool
	UserModule  string
	ProjectRoot string
	ModCache    string            // GOMODCACHE for resolving module sources
	AllModules  map[string]string // path -> version (from go list -m all)
	Stdlib      map[string]bool   // cached stdlib packages
}

// NewTransitiveResolver creates a new resolver with defaults.
func NewTransitiveResolver(userModule, projectRoot string) *TransitiveResolver {
	r := &TransitiveResolver{
		MaxDepth:    3,
		SkipCGO:     true,
		AllowList:   make(map[string]bool),
		DenyList:    make(map[string]bool),
		UserModule:  userModule,
		ProjectRoot: projectRoot,
		AllModules:  make(map[string]string),
		Stdlib:      cacheStdlibTrans(),
	}

	// Discover GOMODCACHE
	cmd := exec.Command("go", "env", "GOMODCACHE")
	out, err := cmd.Output()
	if err == nil {
		r.ModCache = strings.TrimSpace(string(out))
	}

	return r
}

// cacheStdlibTrans runs `go list std` once and caches the result.
func cacheStdlibTrans() map[string]bool {
	result := make(map[string]bool)
	cmd := exec.Command("go", "list", "std")
	out, err := cmd.Output()
	if err != nil {
		return result
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pkg := strings.TrimSpace(line)
		if pkg != "" {
			result[pkg] = true
		}
	}
	return result
}

// Resolve takes direct symbol usages and returns the full set of modules to inline.
func (r *TransitiveResolver) Resolve(directUsages []*SymbolUsage) ([]string, error) {
	// Build a map of all known modules from go list -m -json all (batched — single process)
	allModules, err := r.listAllModules()
	if err != nil {
		return nil, err
	}
	r.AllModules = allModules

	// Seed BFS with directly-used modules
	directModules := make(map[string]bool)
	for _, u := range directUsages {
		modPath := r.modulePathFromImport(u.ImportPath)
		if modPath != "" {
			directModules[modPath] = true
		}
	}

	type entry struct {
		module string
		depth  int
	}

	queue := []entry{}
	for mod := range directModules {
		queue = append(queue, entry{mod, 0})
	}

	visited := make(map[string]bool)
	var selected []string

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current.module] {
			continue
		}
		visited[current.module] = true

		if r.shouldInline(current.module) {
			selected = append(selected, current.module)
		}

		if current.depth >= r.MaxDepth {
			continue
		}

		// Get transitive deps using the module's go.mod from GOMODCACHE
		deps := r.getModuleDeps(current.module, allModules)
		for _, dep := range deps {
			if !visited[dep] {
				queue = append(queue, entry{dep, current.depth + 1})
			}
		}
	}

	return selected, nil
}

// listAllModules returns all modules from go list -m -json all.
func (r *TransitiveResolver) listAllModules() (map[string]string, error) {
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = r.ProjectRoot
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	modules := make(map[string]string) // path -> version
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var entry struct {
			Path    string `json:"Path"`
			Version string `json:"Version"`
		}
		if err := dec.Decode(&entry); err != nil {
			continue
		}
		if entry.Path != "" {
			modules[entry.Path] = entry.Version
		}
	}

	return modules, nil
}

func (r *TransitiveResolver) shouldInline(modulePath string) bool {
	if modulePath == r.UserModule || strings.HasPrefix(modulePath, r.UserModule+"/") {
		return false
	}

	if !strings.Contains(modulePath, ".") {
		return false
	}

	if r.DenyList[modulePath] {
		return false
	}

	if len(r.AllowList) > 0 && !r.AllowList[modulePath] {
		return false
	}

	if r.SkipCGO && r.hasCGO(modulePath) {
		return false
	}

	return true
}

// getModuleDeps returns the direct dependencies of a module by parsing its go.mod.
func (r *TransitiveResolver) getModuleDeps(modulePath string, allModules map[string]string) []string {
	// Find the module's source directory in GOMODCACHE
	version := allModules[modulePath]
	sourceDir := filepath.Join(r.ModCache, modulePath+"@"+version)

	// Parse the module's go.mod to find its direct dependencies
	cmd := exec.Command("go", "mod", "edit", "-json")
	cmd.Dir = sourceDir
	out, err := cmd.Output()
	if err != nil {
		// Fallback: try go list from project root
		return r.getModuleDepsFallback(modulePath)
	}

	var modInfo struct {
		Require []struct {
			Path string `json:"Path"`
		} `json:"Require"`
	}
	if err := json.Unmarshal(out, &modInfo); err != nil {
		return nil
	}

	var deps []string
	for _, req := range modInfo.Require {
		if req.Path != "" && !r.isStdlib(req.Path) && !r.isUserPackage(req.Path) {
			deps = append(deps, req.Path)
		}
	}

	return deps
}

// getModuleDepsFallback is a fallback using go list from project root.
func (r *TransitiveResolver) getModuleDepsFallback(modulePath string) []string {
	cmd := exec.Command("go", "list", "-f",
		"{{range .Imports}}{{.}} {{end}}",
		modulePath+"/...")
	cmd.Dir = r.ProjectRoot
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var deps []string
	imports := strings.Fields(string(out))
	for _, imp := range imports {
		modPath := r.modulePathFromImport(imp)
		if modPath != "" && !r.isStdlib(imp) && !r.isUserPackage(imp) {
			deps = append(deps, modPath)
		}
	}

	return deps
}

func (r *TransitiveResolver) modulePathFromImport(importPath string) string {
	// Use the batched AllModules map to find which module owns this import path.
	// We match by finding the longest module path that is a prefix of the import.
	var bestMatch string
	for modPath := range r.AllModules {
		if importPath == modPath || strings.HasPrefix(importPath, modPath+"/") {
			if len(modPath) > len(bestMatch) {
				bestMatch = modPath
			}
		}
	}
	return bestMatch
}

func (r *TransitiveResolver) hasCGO(modulePath string) bool {
	cmd := exec.Command("go", "list", "-f", "{{.Cgo}}", modulePath+"/...")
	cmd.Dir = r.ProjectRoot
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "true")
}

func (r *TransitiveResolver) isStdlib(importPath string) bool {
	return r.Stdlib[importPath]
}

func (r *TransitiveResolver) isUserPackage(importPath string) bool {
	return importPath == r.UserModule || strings.HasPrefix(importPath, r.UserModule+"/")
}