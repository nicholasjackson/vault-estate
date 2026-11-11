package manifest

import (
	"fmt"
	"strings"

	"github.com/nicholasjackson/vault-estate/estate"
)

// The rules every policy style builds from. Grants follow the KV v2 rules
// (knowledge gotchas/vault-policy-evaluation.md): a secret's values are
// read and written through <mount>/data/<path>.

// dataPath is the path a policy grants to reach a secret's values.
func dataPath(mount, secretPath string) string {
	return mount + "/data/" + secretPath
}

// caps are the capabilities that give a principal the estate's access to a
// secret: read, or read and write.
func caps(o estate.Ops) []string {
	switch {
	case o.Read && o.Write:
		return []string{"create", "read", "update", "delete"}
	case o.Write:
		return []string{"create", "update", "delete"}
	case o.Read:
		return []string{"read"}
	default:
		return nil
	}
}

// relPrefix is the path that reaches the namespace secretNS from loginNS,
// with a trailing slash: "" when they are the same, i.e. checkout/ from
// unit-a for unit-a/checkout. Policies are relative to their own namespace,
// so a policy above the secrets reaches them by this prefix.
func relPrefix(loginNS, secretNS string) string {
	if loginNS == secretNS {
		return ""
	}

	if loginNS == "" {
		return secretNS + "/"
	}

	return strings.TrimPrefix(secretNS, loginNS+"/") + "/"
}

// renderHCL renders the rules as policy text, one path block per rule, in
// order.
func renderHCL(rules []Rule) string {
	var b strings.Builder
	for i, r := range rules {
		if i > 0 {
			b.WriteString("\n")
		}

		quoted := make([]string, len(r.Capabilities))
		for j, c := range r.Capabilities {
			quoted[j] = fmt.Sprintf("%q", c)
		}

		fmt.Fprintf(&b, "path %q {\n  capabilities = [%s]\n}\n", r.Path, strings.Join(quoted, ", "))
	}

	return b.String()
}

// newPolicy makes a policy from its rules, rendering its text.
func newPolicy(name, style, group string, rules []Rule) *Policy {
	return &Policy{Name: name, Style: style, Group: group, Rules: rules, Text: renderHCL(rules)}
}

// addRule adds the rule unless the policy already has one for its path, as
// a pattern covering many secrets would.
func (p *Policy) addRule(r Rule) {
	for _, have := range p.Rules {
		if have.Path == r.Path {
			return
		}
	}

	p.Rules = append(p.Rules, r)
}

// pattern writes a secret's path in its mount with the segments of the
// given kinds (team, app, env) replaced: by + to match any, or by a
// template filled in at login.
func pattern(sec estate.Secret, replace map[string]string) string {
	var parts []string
	for _, seg := range sec.Segments() {
		if r, ok := replace[seg.Kind]; ok {
			parts = append(parts, r)
		} else {
			parts = append(parts, seg.Name)
		}
	}

	return strings.Join(append(parts, sec.Name), "/")
}
