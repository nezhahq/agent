package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestRuntimeConfigConsumerProductionAgentConfigAccessAllowlist(t *testing.T) {
	// Given
	want := []string{
		"commands/edit.go:EditAgentConfig:parameter",
		"commands/edit.go:EditAgentConfig:selector:DNS",
		"commands/edit.go:EditAgentConfig:selector:DNS",
		"commands/edit.go:EditAgentConfig:selector:DNS",
		"commands/edit.go:EditAgentConfig:selector:DNS",
		"commands/edit.go:EditAgentConfig:selector:Debug",
		"commands/edit.go:EditAgentConfig:selector:GPU",
		"commands/edit.go:EditAgentConfig:selector:HardDrivePartitionAllowlist",
		"commands/edit.go:EditAgentConfig:selector:HardDrivePartitionAllowlist",
		"commands/edit.go:EditAgentConfig:selector:HardDrivePartitionAllowlist",
		"commands/edit.go:EditAgentConfig:selector:NICAllowlist",
		"commands/edit.go:EditAgentConfig:selector:NICAllowlist",
		"commands/edit.go:EditAgentConfig:selector:Read",
		"commands/edit.go:EditAgentConfig:selector:Save",
		"commands/edit.go:EditAgentConfig:selector:Temperature",
		"commands/edit.go:EditAgentConfig:selector:UUID",
		"commands/edit.go:EditAgentConfig:selector:UUID",
		"main.go:<package>:declaration",
		"main.go:main:address",
		"main.go:main:address",
		"main.go:preRun:selector:Read",
		"main.go:preRun:argument:publishRuntimeConfig",
		"main.go:runService:selector:Read",
		"runtime_config.go:applyCommittedRuntimeConfig:assignment",
	}
	sort.Strings(want)

	// When
	got := collectProductionAgentConfigAccesses(t)

	// Then
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("production agentConfig access changed\n got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func collectProductionAgentConfigAccesses(t *testing.T) []string {
	t.Helper()
	var accesses []string
	for _, directory := range []string{".", "commands"} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(directory, name)
			displayPath := filepath.ToSlash(path)
			displayPath = strings.TrimPrefix(displayPath, "./")
			fileSet := token.NewFileSet()
			parsed, err := parser.ParseFile(fileSet, filepath.Clean(path), nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", displayPath, err)
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				identifier, ok := node.(*ast.Ident)
				if !ok || identifier.Name != "agentConfig" {
					return true
				}
				accesses = append(accesses, fmt.Sprintf("%s:%s:%s", displayPath, enclosingFunction(parsed, identifier.Pos()), agentConfigAccessContext(parsed, identifier)))
				return true
			})
		}
	}
	sort.Strings(accesses)
	return accesses
}

func enclosingFunction(file *ast.File, position token.Pos) string {
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Pos() <= position && position <= function.End() {
			return function.Name.Name
		}
	}
	return "<package>"
}

func agentConfigAccessContext(file *ast.File, target *ast.Ident) string {
	context := "unknown"
	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.ValueSpec:
			for _, name := range typed.Names {
				if name == target {
					context = "declaration"
					return false
				}
			}
		case *ast.Field:
			for _, name := range typed.Names {
				if name == target {
					context = "parameter"
					return false
				}
			}
		case *ast.SelectorExpr:
			if typed.X == target {
				context = "selector:" + typed.Sel.Name
				return false
			}
		case *ast.UnaryExpr:
			if typed.X == target && typed.Op == token.AND {
				context = "address"
				return false
			}
		case *ast.AssignStmt:
			for _, expression := range typed.Lhs {
				if expression == target {
					context = "assignment"
					return false
				}
			}
		case *ast.CallExpr:
			for _, argument := range typed.Args {
				if argument == target {
					context = "argument:" + calledFunctionName(typed.Fun)
					return false
				}
			}
		}
		return true
	})
	return context
}

func calledFunctionName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	default:
		return "unknown"
	}
}
