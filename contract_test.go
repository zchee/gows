// Copyright 2026 The gows Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gows

import (
	"fmt"
	"go/ast"
	"go/doc"
	"go/doc/comment"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"
)

// cacheLine is the M-series (Apple Silicon) L1 data cache line size the Conn
// field layout is packed against.
const cacheLine = 128

// TestConnFieldLayout pins the cache-line packing of Conn:
// the read-hot working set fits in the first 128-byte line, the write block
// starts on the next 128-byte boundary, and compression-only scratch is pushed
// off both hot lines. It is a layout guard, not a behavioral test: it fails if a
// future field reorder silently regresses the packing.
func TestConnFieldLayout(t *testing.T) {
	var c Conn

	// The write block must start exactly on the second 128B cache line so a
	// concurrent writer's mutex and scratch never share a line with the reader's
	// working set.
	if off := unsafe.Offsetof(c.wmu); off != cacheLine {
		t.Errorf("wmu (write block start) at offset %d, want %d (fresh 128B boundary)", off, cacheLine)
	}

	// Every read-hot field must lie wholly within the first 128B line.
	readHot := []struct {
		name      string
		off, size uintptr
	}{
		{"conn", unsafe.Offsetof(c.conn), unsafe.Sizeof(c.conn)},
		{"rbuf", unsafe.Offsetof(c.rbuf), unsafe.Sizeof(c.rbuf)},
		{"r0", unsafe.Offsetof(c.r0), unsafe.Sizeof(c.r0)},
		{"r1", unsafe.Offsetof(c.r1), unsafe.Sizeof(c.r1)},
		{"hdrTable", unsafe.Offsetof(c.hdrTable), unsafe.Sizeof(c.hdrTable)},
		{"readLimit", unsafe.Offsetof(c.readLimit), unsafe.Sizeof(c.readLimit)},
		{"readErr", unsafe.Offsetof(c.readErr), unsafe.Sizeof(c.readErr)},
		{"msgReader", unsafe.Offsetof(c.msgReader), unsafe.Sizeof(c.msgReader)},
		{"msgBuf", unsafe.Offsetof(c.msgBuf), unsafe.Sizeof(c.msgBuf)},
		{"hdrMaskBit", unsafe.Offsetof(c.hdrMaskBit), unsafe.Sizeof(c.hdrMaskBit)},
		{"client", unsafe.Offsetof(c.client), unsafe.Sizeof(c.client)},
		{"vectored", unsafe.Offsetof(c.vectored), unsafe.Sizeof(c.vectored)},
		{"skipUTF8", unsafe.Offsetof(c.skipUTF8), unsafe.Sizeof(c.skipUTF8)},
		{"msgIsText", unsafe.Offsetof(c.msgIsText), unsafe.Sizeof(c.msgIsText)},
		{"msgCompressed", unsafe.Offsetof(c.msgCompressed), unsafe.Sizeof(c.msgCompressed)},
		{"utf8v", unsafe.Offsetof(c.utf8v), unsafe.Sizeof(c.utf8v)},
	}
	for _, f := range readHot {
		if f.off+f.size > cacheLine {
			t.Errorf("read-hot field %s spans [%d,%d), past the first %dB line", f.name, f.off, f.off+f.size, cacheLine)
		}
	}

	// conn must be first so the hottest transport pointer is at the line head.
	if off := unsafe.Offsetof(c.conn); off != 0 {
		t.Errorf("conn at offset %d, want 0", off)
	}

	// Compression-only scratch must sit below both hot lines (off the write
	// block core), never within the first 128B read line.
	cold := []struct {
		name string
		off  uintptr
	}{
		{"wcomp", unsafe.Offsetof(c.wcomp)},
		{"wslice", unsafe.Offsetof(c.wslice)},
		{"inflateBuf", unsafe.Offsetof(c.inflateBuf)},
		{"deflate", unsafe.Offsetof(c.deflate)},
		{"outgoingWindowCeil", unsafe.Offsetof(c.outgoingWindowCeil)},
	}
	writeCoreEnd := unsafe.Offsetof(c.tornDown)
	for _, f := range cold {
		if f.off < cacheLine {
			t.Errorf("cold field %s at offset %d, want >= %d (off the read line)", f.name, f.off, cacheLine)
		}
		if f.off < writeCoreEnd {
			t.Errorf("cold field %s at offset %d, want after the write-core end %d", f.name, f.off, writeCoreEnd)
		}
	}
}

// --- Exported documentation contract ----------------------------------------

func TestExportedDocumentationContract(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	var issues []string
	for _, entry := range entries {
		if entry.IsDir() || !isRootProductionGoFile(entry.Name()) {
			continue
		}

		file, err := parser.ParseFile(fset, entry.Name(), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		issues = append(issues, exportedDocumentationIssues(fset, file, "gows")...)
	}

	if len(issues) != 0 {
		t.Fatalf("exported documentation contract violations:\n  %s", strings.Join(issues, "\n  "))
	}
}

func TestExportedDocumentationContractAcceptsSupportedDocumentationForms(t *testing.T) {
	tests := []struct{ name, source string }{
		{name: "one line", source: "package gows\n\n// Thing describes a value in one line.\ntype Thing struct{}\n"},
		{name: "multiline", source: "package gows\n\n// Thing describes a value across\n// multiple lines.\ntype Thing struct{}\n"},
		{name: "Go doc link", source: "package gows\n\n// Thing describes a value.\ntype Thing struct{}\n\n// Worker performs work using [Thing].\ntype Worker interface {\n\t// Work performs one unit of work.\n\tWork()\n}\n"},
		{name: "grouped declarations", source: "package gows\n\nconst (\n\t// DefaultThing is the default value.\n\tDefaultThing = 1\n)\n\ntype (\n\t// GroupedThing is a grouped type declaration.\n\tGroupedThing struct{}\n)\n"},
		{name: "directive", source: "package gows\n\n// NewThing constructs a value.\n//\n//go:noinline\nfunc NewThing() int { return 1 }\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if issues := documentationIssuesForSource(t, "fixture.go", test.source); len(issues) != 0 {
				t.Fatalf("documented declaration rejected: %v", issues)
			}
		})
	}
}

func TestExportedDocumentationContractRejectsInvalidDocumentation(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "missing comment",
			source: "package gows\n\ntype Missing struct{}\n",
			want:   "fixture.go:3 Missing: missing doc comment",
		},
		{
			name:   "detached comment",
			source: "package gows\n\n// Detached describes a value.\n\ntype Detached struct{}\n",
			want:   "fixture.go:5 Detached: missing doc comment",
		},
		{
			name:   "missing terminal period",
			source: "package gows\n\n// Unfinished lacks terminal punctuation\ntype Unfinished struct{}\n",
			want:   "fixture.go:4 Unfinished: doc comment must end with a period",
		},
		{
			name:   "undocumented field",
			source: "package gows\n\n// Container contains a value.\ntype Container struct {\n\tValue string\n}\n",
			want:   "fixture.go:5 Value: missing doc comment",
		},
		{
			name:   "undocumented method",
			source: "package gows\n\n// Worker performs work.\ntype Worker interface {\n\tWork()\n}\n",
			want:   "fixture.go:5 Work: missing doc comment",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issues := documentationIssuesForSource(t, "fixture.go", test.source)
			if len(issues) != 1 || issues[0] != test.want {
				t.Fatalf("issues = %q, want [%q]", issues, test.want)
			}
		})
	}
}

func TestExportedDocumentationContractExcludesNonProductionFiles(t *testing.T) {
	for _, name := range []string{"fixture_test.go", "fixture.txt"} {
		if isRootProductionGoFile(name) {
			t.Errorf("isRootProductionGoFile(%q) = true", name)
		}
	}

	issues := documentationIssuesForSource(t, "generated.go", `// Code generated by fixture. DO NOT EDIT.
package gows

type MissingGeneratedComment struct{}
`)
	if len(issues) != 0 {
		t.Fatalf("generated file was checked: %v", issues)
	}

	issues = documentationIssuesForSource(t, "other.go", `package other

type MissingOtherPackageComment struct{}
`)
	if len(issues) != 0 {
		t.Fatalf("non-root package was checked: %v", issues)
	}
}

func documentationIssuesForSource(t *testing.T, name, source string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, source, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return exportedDocumentationIssues(fset, file, "gows")
}

func exportedDocumentationIssues(fset *token.FileSet, file *ast.File, packageName string) []string {
	if file.Name.Name != packageName || ast.IsGenerated(file) {
		return nil
	}
	if _, err := doc.NewFromFiles(fset, []*ast.File{file}, packageName, doc.PreserveAST|doc.AllDecls|doc.AllMethods); err != nil {
		position := fset.Position(file.Package)
		return []string{fmt.Sprintf("%s:%d: extract package documentation: %v", filepath.Base(position.Filename), position.Line, err)}
	}

	var issues []string
	check := func(name *ast.Ident, doc *ast.CommentGroup) {
		if name == nil || !name.IsExported() {
			return
		}
		position := fset.Position(name.Pos())
		prefix := fmt.Sprintf("%s:%d", filepath.Base(position.Filename), position.Line)
		if doc == nil || strings.TrimSpace(doc.Text()) == "" {
			issues = append(issues, prefix+" "+name.Name+": missing doc comment")
			return
		}
		if !docCommentEndsWithPeriod(doc) {
			issues = append(issues, prefix+" "+name.Name+": doc comment must end with a period")
		}
	}

	for _, declaration := range file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			check(declaration.Name, declaration.Doc)
		case *ast.GenDecl:
			for _, spec := range declaration.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					doc := spec.Doc
					if doc == nil && len(declaration.Specs) == 1 {
						doc = declaration.Doc
					}
					check(spec.Name, doc)
					checkFieldDocumentation(check, spec.Type)
				case *ast.ValueSpec:
					doc := spec.Doc
					if doc == nil && len(declaration.Specs) == 1 {
						doc = declaration.Doc
					}
					for _, name := range spec.Names {
						check(name, doc)
					}
				}
			}
		}
	}
	return issues
}

func docCommentEndsWithPeriod(group *ast.CommentGroup) bool {
	parsed := new(comment.Parser).Parse(group.Text())
	printer := new(comment.Printer)
	lastProse := ""
	var visit func([]comment.Block)
	visit = func(blocks []comment.Block) {
		for _, block := range blocks {
			switch block := block.(type) {
			case *comment.Paragraph:
				text := printer.Text(&comment.Doc{Content: []comment.Block{block}})
				lastProse = strings.TrimSpace(string(text))
			case *comment.List:
				for _, item := range block.Items {
					visit(item.Content)
				}
			}
		}
	}
	visit(parsed.Content)
	return strings.HasSuffix(lastProse, ".")
}

func checkFieldDocumentation(check func(*ast.Ident, *ast.CommentGroup), expression ast.Expr) {
	switch expression := expression.(type) {
	case *ast.StructType:
		for _, field := range expression.Fields.List {
			if len(field.Names) == 0 {
				check(embeddedFieldName(field.Type), field.Doc)
				continue
			}
			for _, name := range field.Names {
				check(name, field.Doc)
			}
		}
	case *ast.InterfaceType:
		for _, method := range expression.Methods.List {
			for _, name := range method.Names {
				check(name, method.Doc)
			}
		}
	}
}

func embeddedFieldName(expression ast.Expr) *ast.Ident {
	switch expression := expression.(type) {
	case *ast.Ident:
		return expression
	case *ast.SelectorExpr:
		return expression.Sel
	case *ast.StarExpr:
		return embeddedFieldName(expression.X)
	case *ast.IndexExpr:
		return embeddedFieldName(expression.X)
	case *ast.IndexListExpr:
		return embeddedFieldName(expression.X)
	default:
		return nil
	}
}

func isRootProductionGoFile(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}
