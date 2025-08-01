package module

import (
	"bytes"
	"fmt"
	"github.com/storm-blue/protoc-gen-authorize/authorizer/match"
	"strings"
	"text/template"

	pgs "github.com/lyft/protoc-gen-star"
	pgsgo "github.com/lyft/protoc-gen-star/lang/go"

	"github.com/autom8ter/proto/gen/authorize"
)

// Module is the protoc-gen-authorizer module
// implements the protoc-gen-star module interface
type module struct {
	*pgs.ModuleBase
	pgsgo.Context
	authorizer string
}

func New() pgs.Module {
	return &module{ModuleBase: &pgs.ModuleBase{}}
}

func (m *module) Name() string {
	return "authorize"
}

func (m *module) InitContext(c pgs.BuildContext) {
	m.ModuleBase.InitContext(c)
	m.Context = pgsgo.InitContext(c.Parameters())
	params := c.Parameters()
	m.authorizer = params.Str("authorizer")
	if m.authorizer == "" {
		m.authorizer = "cel"
	}
	m.authorizer = strings.ToLower(m.authorizer)
}

func (m *module) Execute(targets map[string]pgs.File, packages map[string]pgs.Package) []pgs.Artifact {
	// Group files by Go package name to avoid function name conflicts
	packageFiles := make(map[string][]pgs.File)

	for _, f := range targets {
		if f.BuildTarget() {
			// Get the Go package name for this file
			goPackage := m.Context.PackageName(f).String()
			packageFiles[goPackage] = append(packageFiles[goPackage], f)
		}
	}

	// Generate one authorizer file per Go package
	for goPackage, files := range packageFiles {
		m.generateForPackage(goPackage, files)
	}

	return m.Artifacts()
}

// generateForPackage generates a single authorizer file for all services in a Go package
func (m *module) generateForPackage(goPackage string, files []pgs.File) {
	var rules = map[string]*authorize.RuleSet{}
	var firstFile pgs.File // Used for generating the output file name

	// Collect rules from all files in this package
	for _, f := range files {
		if firstFile == nil {
			firstFile = f
		}

		for _, s := range f.Services() {
			for _, method := range s.Methods() {
				var ruleSet authorize.RuleSet
				ok, err := method.Extension(authorize.E_Rules, &ruleSet)
				if err != nil {
					m.AddError(err.Error())
					continue
				}
				if !ok {
					continue
				}

				if m.authorizer == "match" {
					for _, r := range ruleSet.Rules {
						err = match.IsValidExpression(r.Expression)
						if err != nil {
							panic(err)
						}
					}
				}

				// ServiceName_MethodName_FullMethodName
				name := fmt.Sprintf("%s_%s_FullMethodName", s.Name().UpperCamelCase(), method.Name().UpperCamelCase())
				rules[name] = &ruleSet
			}
		}
	}

	if len(rules) == 0 {
		return
	}

	// Generate output filename: use package name instead of individual file name
	// This ensures one authorizer file per Go package
	outputName := strings.ReplaceAll(goPackage, "/", "_") + ".pb.authorizer.go"
	if firstFile != nil {
		// Use the directory of the first file but change the filename
		firstFilePath := firstFile.InputPath().SetExt(".pb.authorizer.go").String()
		dir := strings.TrimSuffix(firstFilePath, firstFile.InputPath().BaseName()+".pb.authorizer.go")
		outputName = dir + outputName
	}

	var (
		t   *template.Template
		err error
	)
	switch m.authorizer {
	case "javascript":
		t, err = template.New("authorizer").Parse(javascriptTmpl)
		if err != nil {
			m.AddError(err.Error())
			return
		}
	case "cel":
		t, err = template.New("authorizer").Parse(celTmpl)
		if err != nil {
			m.AddError(err.Error())
			return
		}
	case "match":
		t, err = template.New("authorizer").Parse(matchTmpl)
		if err != nil {
			m.AddError(err.Error())
			return
		}
	}

	buffer := &bytes.Buffer{}
	if err := t.Execute(buffer, templateData{
		Package: goPackage,
		Rules:   rules,
	}); err != nil {
		m.AddError(err.Error())
		return
	}
	m.AddGeneratorFile(outputName, buffer.String())
}

type templateData struct {
	Package string
	Rules   map[string]*authorize.RuleSet
}

var javascriptTmpl = `
package {{ .Package }}

import (
	"github.com/autom8ter/proto/gen/authorize"

	"github.com/storm-blue/protoc-gen-authorize/authorizer/javascript"
)

// NewAuthorizer returns a new javascript authorizer. The rules map is a map of method names to RuleSets. The RuleSets are used to
// authorize the method. The RuleSets are evaluated in order and the first rule that evaluates to true will authorize
// the request. The mapping can be generated with the protoc-gen-authorize plugin.
func NewAuthorizer(opts ...javascript.Opt) (*javascript.JavascriptAuthorizer, error) {
	return javascript.NewJavascriptAuthorizer(map[string]*authorize.RuleSet{
	{{- range $key, $value := .Rules }}
	{{$key}}: {
		Rules: []*authorize.Rule{
		{{- range $value.Rules }}
			{
				Expression: "{{ .Expression }}",
			},
		{{- end }}
		},
	},
	{{- end }}
}, opts...)
}
`

var celTmpl = `
package {{ .Package }}

import (
	"github.com/autom8ter/proto/gen/authorize"

	"github.com/storm-blue/protoc-gen-authorize/authorizer/cel"
)

// NewAuthorizer returns a new javascript authorizer. The rules map is a map of method names to RuleSets. The RuleSets are used to
// authorize the method. The RuleSets are evaluated in order and the first rule that evaluates to true will authorize
// the request. The mapping can be generated with the protoc-gen-authorize plugin.
func NewAuthorizer(opts ...cel.Opt) (*cel.CelAuthorizer, error) {
	return cel.NewCelAuthorizer(map[string]*authorize.RuleSet{
	{{- range $key, $value := .Rules }}
	{{$key}}: {
		Rules: []*authorize.Rule{
		{{- range $value.Rules }}
			{
				Expression: "{{ .Expression }}",
			},
		{{- end }}
		},
	},
	{{- end }}
}, opts...)
}
`

var matchTmpl = `
package {{ .Package }}

import (
	"github.com/autom8ter/proto/gen/authorize"

	"github.com/storm-blue/protoc-gen-authorize/authorizer/match"
)

// NewAuthorizer returns a new javascript authorizer. The rules map is a map of method names to RuleSets. The RuleSets are used to
// authorize the method. The RuleSets are evaluated in order and the first rule that evaluates to true will authorize
// the request. The mapping can be generated with the protoc-gen-authorize plugin.
func NewAuthorizer(opts ...match.Opt) (*match.MatchAuthorizer, error) {
	return match.NewBatchAuthorizer(map[string]*authorize.RuleSet{
	{{- range $key, $value := .Rules }}
	{{$key}}: {
		Rules: []*authorize.Rule{
		{{- range $value.Rules }}
			{
				Expression: "{{ .Expression }}",
			},
		{{- end }}
		},
	},
	{{- end }}
}, opts...)
}
`
