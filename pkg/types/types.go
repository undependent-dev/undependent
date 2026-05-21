// Package types provides the shared types for undep.
package types

import (
	"go/ast"
)

// SymbolKind classifies what kind of Go symbol this is.
type SymbolKind int

const (
	Func SymbolKind = iota
	Type
	Var
	Const
	Interface
)

// SymbolRef tracks a single exported identifier across the dependency graph.
type SymbolRef struct {
	Name       string      // "DefaultWriter", "Context", etc.
	Kind       SymbolKind
	DefinedIn  *FileNode   // where it's defined (source file)
	UsedIn     []*FileNode // where it's referenced (user code + deps)
	ImportPath string      // the import path needed to access it
	Depth      int         // BFS depth from user code (0 = directly used)
}

// ModuleNode represents a single dependency (e.g., github.com/gin-gonic/gin).
type ModuleNode struct {
	Path       string        // "github.com/gin-gonic/gin"
	Version    string        // "v1.9.1"
	Indirect   bool          // true if only a transitive dependency
	SourceDir  string        // absolute path to module source on disk
	Packages   []*PkgNode    // sub-packages within this module
	RequiredBy []*ModuleNode // reverse deps: who requires this module?
	Selected   bool          // was this module selected for inlining?
	HasCGO     bool          // true if any package uses cgo
	License    LicenseInfo   // detected license
}

// PkgNode represents a single Go package within a module.
type PkgNode struct {
	Module     *ModuleNode
	ImportPath string       // "github.com/gin-gonic/gin/binding"
	Name       string       // package name (e.g., "binding")
	Files      []*FileNode  // .go files in this package
	Exported   []*SymbolRef // exported symbols defined here
}

// FileNode represents a single .go source file.
type FileNode struct {
	Path    string    // absolute path on disk
	RelPath string    // path relative to module root
	Package string    // package name
	AST     *ast.File // parsed AST (nil if not yet parsed)
	Symbols []*SymbolRef // symbols defined in this file
}

// LicenseInfo tracks license obligations for a module.
type LicenseInfo struct {
	Type    string   // "MIT", "Apache-2.0", "BSD-3-Clause", "Unknown"
	File    string   // path to LICENSE file within module
	Authors []string // copyright holders
	Viral   bool     // true for GPL-family (AGPL, GPL, LGPL)
}

// DepGraph represents the full dependency tree of a Go module.
type DepGraph struct {
	Root  *ModuleNode          // the user's project
	Nodes map[string]*ModuleNode // keyed by module path
	ByPkg map[string]*PkgNode    // keyed by import path
}

// InlineResult contains the output of an inlining operation.
type InlineResult struct {
	ModulesInlined    int
	PackagesInlined   int
	FilesInlined      int
	SymbolsInlined    int
	ReplaceDirectives []string // go.mod replace directives generated
	LicenseManifest   string   // LICENSE.absorbed content
	Errors            []error
	Warnings          []string
}