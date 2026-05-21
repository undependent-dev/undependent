// Package analyze scans user code to find which dependency symbols are used.
package analyze

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Analyzer scans a Go project to find external symbol usage.
type Analyzer struct {
	Fset       *token.FileSet
	Conf       *types.Config
	UserRoot   string
	UserModule string
	Stdlib     map[string]bool // cached stdlib packages
}

// NewAnalyzer creates a new Analyzer.
func NewAnalyzer(userRoot, userModule string) *Analyzer {
	fset := token.NewFileSet()
	conf := &types.Config{}
	return &Analyzer{
		Fset:       fset,
		Conf:       conf,
		UserRoot:   userRoot,
		UserModule: userModule,
		Stdlib:     cacheStdlib(),
	}
}

// cacheStdlib runs `go list std` once and caches the result.
func cacheStdlib() map[string]bool {
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

// SymbolUsage represents a single external symbol used by user code.
type SymbolUsage struct {
	Name       string
	ImportPath string
	Kind       string
	File       string
	Line       int
}

// Scan walks all user .go files and returns external symbol usages.
func (a *Analyzer) Scan() ([]*SymbolUsage, error) {
	var usages []*SymbolUsage
	seen := make(map[string]bool)

	err := filepath.Walk(a.UserRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		name := info.Name()

		if info.IsDir() {
			if name == "vendor" || name == ".git" || name == "node_modules" ||
				strings.HasPrefix(name, "internal/absorbed") ||
				strings.HasPrefix(name, "undep") {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}

		usage, err := a.scanFile(path)
		if err != nil {
			return nil
		}

		for _, u := range usage {
			key := u.ImportPath + "." + u.Name
			if !seen[key] {
				seen[key] = true
				usages = append(usages, u)
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk user code: %w", err)
	}

	return usages, nil
}

func (a *Analyzer) scanFile(filename string) ([]*SymbolUsage, error) {
	fset := token.NewFileSet()

	file, err := parser.ParseFile(fset, filename, nil, parser.AllErrors)
	if err != nil {
		return nil, err
	}

	info := &types.Info{
		Uses: make(map[*ast.Ident]types.Object),
		Defs: make(map[*ast.Ident]types.Object),
	}

	conf := &types.Config{}

	_, err = conf.Check("", fset, []*ast.File{file}, info)
	if err != nil {
		return a.scanFileAST(file, fset)
	}

	return a.scanFileTyped(file, fset, info)
}

func (a *Analyzer) scanFileTyped(file *ast.File, fset *token.FileSet, info *types.Info) ([]*SymbolUsage, error) {
	var usages []*SymbolUsage

	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		obj := info.Uses[sel.Sel]
		if obj == nil {
			return true
		}

		pkg := obj.Pkg()
		if pkg == nil {
			return true
		}

		importPath := pkg.Path()

		if a.isStdlib(importPath) || a.isUserPackage(importPath) {
			return true
		}

		pos := fset.Position(sel.Pos())
		usages = append(usages, &SymbolUsage{
			Name:       obj.Name(),
			ImportPath: importPath,
			Kind:       a.kindString(obj),
			File:       pos.Filename,
			Line:       pos.Line,
		})

		return true
	})

	return usages, nil
}

func (a *Analyzer) scanFileAST(file *ast.File, fset *token.FileSet) ([]*SymbolUsage, error) {
	var usages []*SymbolUsage

	imports := make(map[string]string)
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		name := path
		if imp.Name != nil {
			if imp.Name.Name == "." {
				name = "."
			} else {
				name = imp.Name.Name
			}
		} else {
			parts := strings.Split(path, "/")
			name = parts[len(parts)-1]
		}
		imports[name] = path
	}

	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		receiver, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		importPath, ok := imports[receiver.Name]
		if !ok {
			return true
		}

		if a.isStdlib(importPath) || a.isUserPackage(importPath) {
			return true
		}

		pos := fset.Position(sel.Pos())
		usages = append(usages, &SymbolUsage{
			Name:       sel.Sel.Name,
			ImportPath: importPath,
			Kind:       "unknown",
			File:       pos.Filename,
			Line:       pos.Line,
		})

		return true
	})

	return usages, nil
}

func (a *Analyzer) isStdlib(importPath string) bool {
	return a.Stdlib[importPath]
}

func (a *Analyzer) isUserPackage(importPath string) bool {
	return importPath == a.UserModule || strings.HasPrefix(importPath, a.UserModule+"/")
}

func (a *Analyzer) kindString(obj types.Object) string {
	switch obj.(type) {
	case *types.Func:
		return "func"
	case *types.TypeName:
		return "type"
	case *types.Var:
		return "var"
	case *types.Const:
		return "const"
	default:
		return "unknown"
	}
}