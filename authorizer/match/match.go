package match

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/autom8ter/proto/gen/authorize"

	"github.com/storm-blue/protoc-gen-authorize/authorizer"
)

// Opt is a functional option for configuring a MatchAuthorizer
type Opt func(*MatchAuthorizer)

// MatchAuthorizer is a javascript vm that uses javascript expressions to authorize grpc requests
type MatchAuthorizer struct {
	rules map[string]*authorize.RuleSet
}

// NewMatchAuthorizer returns a new MatchAuthorizer. The rules map is a map of method names to RuleSets. The RuleSets are used to
// authorize the method. The RuleSets are evaluated in order and the first rule that evaluates to true will authorize
// the request. The mapping can be generated with the protoc-gen-authorize plugin.
func NewMatchAuthorizer(rules map[string]*authorize.RuleSet, opts ...Opt) (*MatchAuthorizer, error) {
	a := &MatchAuthorizer{
		rules: rules,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// AuthorizeMethod authorizes a gRPC method the RuleExecutionParams and returns a boolean representing whether the
// request is authorized or not.
func (a *MatchAuthorizer) AuthorizeMethod(ctx context.Context, method string, params *authorizer.RuleExecutionParams) (bool, error) {
	// return false if no rules exist for the method
	rules, ok := a.rules[method]
	if !ok {
		svc := strings.Split(method, "/")[1]
		for k := range a.rules {
			if strings.HasPrefix(k, "/"+svc) {
				return true, nil
			}
		}
		return false, nil
	}

	var (
		metaMap = map[string]string{}
	)
	for k, v := range params.Metadata {
		metaMap[k] = strings.Join(v, ",")
	}

	permissions, err := GetPermissions(params.User)
	if err != nil {
		return false, fmt.Errorf("authorizer: failed to get permissions: %v", err.Error())
	}

	if len(permissions) == 0 {
		return false, fmt.Errorf("authorizer: user does not have any permissions")
	}

	data := map[string]interface{}{
		"metadata": metaMap,
		"request":  params.Request,
		"user":     params.User,
		"rule":     rules,
	}

	expressions := getExpressions(rules)
	needPermissions, err := getNeedPermissions(expressions, data)
	if err != nil {
		return false, err
	}

	return permissionsMatch(needPermissions, permissions)
}

var parseKyeRegex = regexp.MustCompile(`\${([^{}]+)}`)

func parseKeys(template string) []string {
	matches := parseKyeRegex.FindAllStringSubmatch(template, -1)

	keys := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			keys = append(keys, match[1])
		}
	}
	return keys
}

func IsValidExpression(expression string) error {
	keys := parseKeys(expression)
	for _, key := range keys {
		if err := validateKey(key); err != nil {
			return err
		}
	}

	_, err := buildGoTemplate(convertToGoTemplate(expression))
	return err
}

var validKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*$`)

func validateKey(key string) error {
	if key == "user.Permissions" {
		return fmt.Errorf("user.Permissions is not allowed")
	}
	if !validKeyRegex.MatchString(key) {
		return fmt.Errorf("invalid key: %s", key)
	}
	return nil
}

func permissionsMatch(needPermissions []string, permissions []string) (bool, error) {
	for _, needPermission := range needPermissions {
		for _, permission := range permissions {
			match, err := permissionMatch(needPermission, permission)
			if err != nil {
				return false, err
			}
			if match {
				return true, nil
			}
		}
	}
	return false, nil
}

func permissionMatch(needPermission string, permission string) (bool, error) {
	permissionRegexStr := strings.ReplaceAll(permission, ".", "\\.")
	permissionRegexStr = strings.ReplaceAll(permissionRegexStr, "*", "[a-zA-Z0-9_/\\.]*")
	permissionRegex, err := regexp.Compile(permissionRegexStr)
	if err != nil {
		return false, err
	}

	if permissionRegex.MatchString(needPermission) {
		return true, nil
	}

	return false, nil
}

func convertToGoTemplate(t1 string) string {
	keys := parseKeys(t1)
	_t := t1
	for _, key := range keys {
		_t = strings.ReplaceAll(_t, "${"+key+"}", "${."+key+"}")
	}
	return _t
}

func buildGoTemplate(t1 string) (*template.Template, error) {
	return template.New("").Delims("${", "}").Parse(t1)
}

func rendNeedPermission(t1 string, data map[string]interface{}) (string, error) {
	tmpl, err := buildGoTemplate(t1)
	if err != nil {
		return "", err
	}
	buffer := &strings.Builder{}
	if err := tmpl.Execute(buffer, data); err != nil {
		return "", err
	}
	return buffer.String(), nil
}

func getNeedPermissions(expressions []string, data map[string]interface{}) ([]string, error) {
	var needPermissions []string

	for _, expression := range expressions {
		_t := convertToGoTemplate(expression)
		needPermission, err := rendNeedPermission(_t, data)
		if err != nil {
			return nil, err
		}
		needPermissions = append(needPermissions, needPermission)
	}
	return needPermissions, nil
}

func getExpressions(rules *authorize.RuleSet) []string {
	var expressions []string
	for _, rule := range rules.Rules {
		expressions = append(expressions, rule.Expression)
	}
	return expressions
}
