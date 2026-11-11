package manifest

import (
	"strings"

	"github.com/nicholasjackson/vault-estate/estate"
)

// scope is a place in the customer's Vault: a cluster and a namespace in it,
// "" for the root.
type scope struct {
	Cluster, Namespace string
}

// placement is where an app's secrets sit: its scope and its KV mount. Every
// one of an app's secrets is in the same mount.
type placement struct {
	scope
	Mount string
}

// placements returns where each app's secrets sit.
func placements(p *estate.Plan) map[*estate.App]placement {
	out := map[*estate.App]placement{}
	for _, c := range p.Clusters {
		for _, ns := range c.Namespaces {
			for _, m := range ns.Mounts {
				for _, sec := range m.Secrets {
					out[sec.App] = placement{scope{c.Name, ns.Path}, m.Path}
				}
			}
		}
	}

	return out
}

// loginScope is where people whose secrets sit at s log in: on community,
// the cluster itself (it has only the root namespace); on enterprise, the
// root or the unit's namespace, as the model's user_auth says.
func loginScope(p *estate.Plan, s scope, model string) scope {
	if p.Edition != estate.EditionEnterprise || p.UserAuth(model) == estate.UserAuthRoot {
		return scope{s.Cluster, ""}
	}

	unit, _, _ := strings.Cut(s.Namespace, "/")

	return scope{s.Cluster, unit}
}

// commonAncestor is the deepest namespace at or above every one of the
// namespaces, "" when they only share the root.
func commonAncestor(namespaces []string) string {
	if len(namespaces) == 0 {
		return ""
	}

	common := strings.Split(namespaces[0], "/")
	for _, ns := range namespaces[1:] {
		parts := strings.Split(ns, "/")

		n := 0
		for n < len(common) && n < len(parts) && common[n] == parts[n] {
			n++
		}

		common = common[:n]
	}

	return strings.Join(common, "/")
}
