// Package graph builds the dependency graph from go.mod.
package graph

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/undep/undep/pkg/types"
)

// Resolver builds a DepGraph by parsing go.mod and fetching source.
type Resolver struct {
	ProjectRoot string
	ModCache    string // GOMODCACHE path
}

// NewResolver creates a new Resolver.
func NewResolver(projectRoot string) *Resolver {
	r := &Resolver{ProjectRoot: projectRoot}
	// Discover GOMODCACHE
	cmd := exec.Command("go", "env", "GOMODCACHE")
	out, err := cmd.Output()
	if err == nil {
		r.ModCache = strings.TrimSpace(string(out))
	}
	return r
}

// Resolve builds the complete dependency graph.
func (r *Resolver) Resolve() (*types.DepGraph, error) {
	if err := r.downloadModules(); err != nil {
		return nil, fmt.Errorf("download modules: %w", err)
	}

	deps, err := r.listAllDeps()
	if err != nil {
		return nil, fmt.Errorf("list deps: %w", err)
	}

	graph := &types.DepGraph{
		Nodes: make(map[string]*types.ModuleNode),
		ByPkg: make(map[string]*types.PkgNode),
	}

	for _, dep := range deps {
		node := r.resolveModule(dep)
		graph.Nodes[dep.Path] = node

		pkgs := r.discoverPackages(node)
		node.Packages = pkgs

		for _, pkg := range pkgs {
			graph.ByPkg[pkg.ImportPath] = pkg
		}
	}

	r.buildReverseEdges(graph)

	return graph, nil
}

type depEntry struct {
	Path     string
	Version  string
	Indirect bool
}

func (r *Resolver) listAllDeps() ([]depEntry, error) {
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = r.ProjectRoot
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Use json.Decoder to properly parse multi-line JSON objects
	var deps []depEntry
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var entry depEntry
		if err := dec.Decode(&entry); err != nil {
			continue
		}
		if entry.Path != "" {
			deps = append(deps, entry)
		}
	}

	return deps, nil
}

func (r *Resolver) downloadModules() error {
	cmd := exec.Command("go", "mod", "download")
	cmd.Dir = r.ProjectRoot
	_, err := cmd.Output()
	return err
}

// moduleSourceDir constructs the source directory for a module from GOMODCACHE.
// Go stores modules as: $GOMODCACHE/github.com/gin-gonic/gin@v1.9.1/
func (r *Resolver) moduleSourceDir(path, version string) string {
	if r.ModCache == "" {
		return ""
	}
	return filepath.Join(r.ModCache, path+"@"+version)
}

func (r *Resolver) resolveModule(dep depEntry) *types.ModuleNode {
	sourceDir := r.moduleSourceDir(dep.Path, dep.Version)

	node := &types.ModuleNode{
		Path:      dep.Path,
		Version:   dep.Version,
		Indirect:  dep.Indirect,
		SourceDir: sourceDir,
	}

	// Check for CGO
	cmd := exec.Command("go", "list", "-f", "{{.Cgo}}", dep.Path+"/...")
	cmd.Dir = r.ProjectRoot
	out, _ := cmd.Output()
	if strings.Contains(string(out), "true") {
		node.HasCGO = true
	}

	return node
}

func (r *Resolver) discoverPackages(node *types.ModuleNode) []*types.PkgNode {
	cmd := exec.Command("go", "list", "-f",
		"{{.ImportPath}}|{{.Name}}|{{.Dir}}",
		node.Path+"/...")
	cmd.Dir = r.ProjectRoot
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var pkgs []*types.PkgNode
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 3 {
			continue
		}

		importPath := parts[0]
		pkgName := parts[1]
		pkgDir := parts[2]

		if strings.Contains(importPath, ".test") {
			continue
		}

		pkgNode := &types.PkgNode{
			Module:     node,
			ImportPath: importPath,
			Name:       pkgName,
		}

		pkgNode.Files = r.discoverFiles(pkgNode, pkgDir)
		pkgs = append(pkgs, pkgNode)
	}

	return pkgs
}

func (r *Resolver) discoverFiles(pkg *types.PkgNode, pkgDir string) []*types.FileNode {
	var files []*types.FileNode

	entries, err := filepath.Glob(filepath.Join(pkgDir, "*.go"))
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry, "_test.go") {
			continue
		}

		files = append(files, &types.FileNode{
			Path:    entry,
			RelPath: strings.TrimPrefix(entry, pkgDir+"/"),
			Package: pkg.Name,
		})
	}

	return files
}

func (r *Resolver) buildReverseEdges(graph *types.DepGraph) {
	for path, node := range graph.Nodes {
		cmd := exec.Command("go", "list", "-f",
			"{{range .Imports}}{{.}} {{end}}",
			path+"/...")
		cmd.Dir = r.ProjectRoot
		out, _ := cmd.Output()

		imports := strings.Fields(string(out))
		for _, imp := range imports {
			if dep, ok := graph.Nodes[imp]; ok {
				dep.RequiredBy = append(dep.RequiredBy, node)
			}
		}
	}
}