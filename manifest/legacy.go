package manifest

import (
	"slices"
	"strings"

	"github.com/nicholasjackson/vault-estate/estate"
)

// The quirks the legacy style marks on its policies, so tests and readers
// can tell deliberate mess from a bug.
const (
	QuirkWildcard      = "wildcard"
	QuirkDeadRule      = "dead-rule"
	QuirkEnvWide       = "env-wide"
	QuirkDeny          = "deny"
	QuirkSudo          = "sudo"
	QuirkNearDuplicate = "near-duplicate"
	QuirkOrphan        = "orphan"
)

// legacy writes an ops group's policies in the legacy style, reproducing
// the mess real estates accumulate (knowledge
// gotchas/vault-policy-evaluation.md):
//
//   - the group's shared AppRole, <group>-legacy, present even with no
//     legacy apps, with a group-wide wildcard and a KV v1-style rule that
//     matches nothing
//   - the group's other apps get <team>-<app>, reading everything under
//     the app with no environment split
//   - developers and testers get environment-wide <group>-<env> policies,
//     the last environment's with a deny carve-out on db/admin, and
//     developers <group>-<first env>-rw as well
//   - the manager gets <group>-read-all
//   - ops engineers and their ops manager get <group>-ops-admin, carrying
//     sudo the paths don't need, and its near-duplicate <group>-ops-admin-v2
//   - an orphan, <group>-<app>-old, for an app that no longer exists,
//     attached to nothing
func (g *generator) legacy(group *estate.OpsGroup) {
	g.legacyRoles(group)

	for _, team := range group.Teams {
		for _, a := range team.Apps {
			if a.Platform != estate.PlatformLegacy {
				g.legacyAppPolicy(group, a)
			}
		}
	}

	envs := g.environments(group)
	first, last := envs[0], envs[len(envs)-1]

	devsAndTesters := func(person *estate.Person) bool {
		return person.Group == group && (person.Kind == estate.KindDeveloper || person.Kind == estate.KindTester)
	}

	var people []peoplePolicy
	for _, env := range envs {
		quirks := []string{QuirkEnvWide}
		if env == last {
			quirks = append(quirks, QuirkDeny)
		}

		people = append(people, peoplePolicy{
			Name: group.Name + "-" + envName(env), Teams: group.Teams, Member: devsAndTesters, Quirks: quirks,
			Rules: func(sec estate.Secret) []Rule {
				if sec.Env != env {
					return nil
				}

				out := []Rule{{Path: "data/" + envPrefix(sec) + "*", Capabilities: []string{"read"}}}
				if env == last && sec.Thing == "db" && sec.Name == "admin" {
					out = append(out, Rule{Path: "data/" + pattern(sec, map[string]string{"team": "+", "app": "+"}), Capabilities: []string{"deny"}})
				}

				return out
			},
		})
	}

	people = append(people,
		peoplePolicy{
			Name: group.Name + "-" + envName(first) + "-rw", Teams: group.Teams, Member: groupKind(group, estate.KindDeveloper), Quirks: []string{QuirkEnvWide},
			Rules: func(sec estate.Secret) []Rule {
				if sec.Env != first {
					return nil
				}

				return []Rule{{Path: "data/" + envPrefix(sec) + "*", Capabilities: []string{"create", "read", "update", "delete"}}}
			},
		},
		peoplePolicy{
			Name: group.Name + "-read-all", Teams: group.Teams, Member: groupKind(group, estate.KindManager), Quirks: []string{QuirkWildcard},
			Rules: func(sec estate.Secret) []Rule {
				return []Rule{{Path: "data/" + groupPrefix(sec) + "*", Capabilities: []string{"read"}}}
			},
		},
	)

	for _, name := range []string{group.Name + "-ops-admin", group.Name + "-ops-admin-v2"} {
		data := []string{"create", "read", "update", "delete", "list", "sudo"}
		if strings.HasSuffix(name, "-v2") {
			data = append(data, "patch")
		}

		ops := opsPolicy(group, nil)
		ops.Name, ops.Quirks = name, []string{QuirkSudo, QuirkNearDuplicate}
		ops.Rules = func(sec estate.Secret) []Rule {
			return []Rule{
				{Path: "data/" + groupPrefix(sec) + "*", Capabilities: data},
				{Path: "metadata/" + groupPrefix(sec) + "*", Capabilities: []string{"read", "list", "delete", "sudo"}},
			}
		}

		people = append(people, ops)
	}

	for _, pp := range people {
		g.peoplePolicy(group, pp)
	}

	g.orphan(group)
}

// legacyRoles makes sure the group has its shared AppRole in every cluster
// holding its apps, in the nearest namespace above them all, even with no
// legacy apps there, and gives each a policy with a group-wide wildcard and
// a KV v1-style rule left over from before the upgrade to KV v2.
func (g *generator) legacyRoles(group *estate.OpsGroup) {
	var clusters []string
	namespaces := map[string][]string{}
	for _, team := range group.Teams {
		for _, a := range team.Apps {
			at := g.placed[a]
			if namespaces[at.Cluster] == nil {
				clusters = append(clusters, at.Cluster)
			}

			namespaces[at.Cluster] = append(namespaces[at.Cluster], at.Namespace)
		}
	}

	name := LegacyRole(group.Name)
	for _, cluster := range clusters {
		ref, ok := g.findRole(cluster, approleMount, name)
		if !ok {
			ref = g.addRole(scope{cluster, commonAncestor(namespaces[cluster])}, approleMount, TypeAppRole, Role{
				Name: name, Apps: []string{},
				Config: map[string]any{"token_type": "service"},
			})
		}

		p := newPolicy(name, group.Style, group.Name, nil)
		p.Quirks = []string{QuirkWildcard, QuirkDeadRule}

		for _, team := range group.Teams {
			for _, a := range team.Apps {
				at := g.placed[a]
				if at.Cluster != cluster || !below(ref.Namespace, at.Namespace) {
					continue
				}

				rel := relPrefix(ref.Namespace, at.Namespace)
				for _, sec := range g.secretsOf[a] {
					prefix := groupPrefix(sec)
					p.addRule(Rule{Path: rel + at.Mount + "/data/" + prefix + "*", Capabilities: []string{"create", "read", "update", "delete", "list"}})
					p.addRule(Rule{Path: rel + at.Mount + "/" + prefix + "*", Capabilities: []string{"read"}})
				}
			}
		}

		p.Text = renderHCL(p.Rules)
		g.addPolicy(ref.scope, p)
		g.rolePolicies[ref] = append(g.rolePolicies[ref], name)
	}
}

// findRole finds the role called name on the mount at path anywhere in the
// cluster.
func (g *generator) findRole(cluster, path, name string) (roleRef, bool) {
	for at, mounts := range g.auth {
		if at.Cluster != cluster || mounts[path] == nil {
			continue
		}

		for _, r := range mounts[path].Roles {
			if r.Name == name {
				return roleRef{at, path, name}, true
			}
		}
	}

	return roleRef{}, false
}

// legacyAppPolicy gives an app of a legacy group <team>-<app>, reading
// everything under the app in every environment.
func (g *generator) legacyAppPolicy(group *estate.OpsGroup, a *estate.App) {
	role := g.roleOf[a]
	at := g.placed[a]
	rel := relPrefix(role.Namespace, at.Namespace)

	p := newPolicy(AppID(a), group.Style, group.Name, nil)
	p.Quirks = []string{QuirkWildcard}
	for _, sec := range g.secretsOf[a] {
		p.addRule(Rule{Path: rel + at.Mount + "/data/" + appPrefix(sec) + "*", Capabilities: []string{"read"}})
	}

	p.Text = renderHCL(p.Rules)
	g.addPolicy(role.scope, p)
	g.rolePolicies[role] = append(g.rolePolicies[role], p.Name)
}

// orphan writes a policy for an app that no longer exists, named after a
// supporting app none of the group's teams runs, with a KV v1-style rule,
// next to the group's first shared AppRole and attached to nothing.
func (g *generator) orphan(group *estate.OpsGroup) {
	var used []string
	var first *estate.App
	for _, team := range group.Teams {
		for _, a := range team.Apps {
			used = append(used, a.Name)
			if first == nil {
				first = a
			}
		}
	}

	var unused []string
	for _, name := range estate.SupportAppNames() {
		if !slices.Contains(used, name) {
			unused = append(unused, name)
		}
	}

	word := unused[g.values.r.IntN(len(unused))]

	role, _ := g.findRole(g.placed[first].Cluster, approleMount, LegacyRole(group.Name))
	at := g.placed[first]
	rel := relPrefix(role.Namespace, at.Namespace)
	sec := g.secretsOf[first][0]

	p := newPolicy(group.Name+"-"+word+"-old", group.Style, group.Name, []Rule{
		{Path: rel + at.Mount + "/" + groupPrefix(sec) + word + "/*", Capabilities: []string{"read"}},
	})
	p.Quirks = []string{QuirkOrphan, QuirkDeadRule}
	g.addPolicy(role.scope, p)
}

// environments are the environments the group's secrets are in, in the
// customer's order; "" alone when the models leave the environment out.
func (g *generator) environments(group *estate.OpsGroup) []string {
	var envs []string
	for _, team := range group.Teams {
		for _, a := range team.Apps {
			for _, sec := range g.secretsOf[a] {
				if !slices.Contains(envs, sec.Env) {
					envs = append(envs, sec.Env)
				}
			}
		}
	}

	order := append(slices.Clone(g.plan.Environments), "")
	slices.SortStableFunc(envs, func(a, b string) int {
		return slices.Index(order, a) - slices.Index(order, b)
	})

	return envs
}

// envName names an environment in a policy name: all when there is none.
func envName(env string) string {
	if env == "" {
		return "all"
	}

	return env
}

// groupPrefix is the part of a secret's path above its team, with the
// environment as + when it comes first, and a trailing slash; "" when the
// team comes first.
func groupPrefix(sec estate.Secret) string {
	var parts []string
	for _, seg := range sec.Segments() {
		if seg.Kind == "team" {
			break
		}

		if seg.Kind == "env" {
			parts = append(parts, "+")
		} else {
			parts = append(parts, seg.Name)
		}
	}

	return withSlash(parts)
}

// envPrefix is the part of a secret's path that pins its environment, with
// the team and app as +: up to the environment when it comes after the
// app, or up to the team when it comes first.
func envPrefix(sec estate.Secret) string {
	segs := sec.Segments()

	end := len(segs)
	for i, seg := range segs {
		if seg.Kind == "team" {
			end = i
		}
	}

	for i, seg := range segs {
		if seg.Kind == "env" && i >= end {
			end = i + 1
		}
	}

	var parts []string
	for _, seg := range segs[:end] {
		switch seg.Kind {
		case "team", "app":
			parts = append(parts, "+")
		default:
			parts = append(parts, seg.Name)
		}
	}

	return withSlash(parts)
}

// appPrefix is the part of a secret's path down to its app (its team when
// the app has a namespace of its own), with the environment as + when it
// comes first.
func appPrefix(sec estate.Secret) string {
	var parts []string
	for _, seg := range sec.Segments() {
		if seg.Kind == "env" {
			if len(parts) > 0 {
				break
			}

			parts = append(parts, "+")

			continue
		}

		if seg.Kind == "thing" {
			break
		}

		parts = append(parts, seg.Name)
		if seg.Kind == "app" {
			break
		}
	}

	return withSlash(parts)
}

// below reports whether namespace ns is at or below namespace top.
func below(top, ns string) bool {
	return top == "" || ns == top || strings.HasPrefix(ns, top+"/")
}

func withSlash(parts []string) string {
	if len(parts) == 0 {
		return ""
	}

	return strings.Join(parts, "/") + "/"
}
