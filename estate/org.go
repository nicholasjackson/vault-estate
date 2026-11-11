package estate

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
)

const (
	// AppsPerTeam is how many apps a team of about 8 runs.
	AppsPerTeam = 3
	// Span is how many reports a manager has, at every layer.
	Span = 4
)

// Node is a part of the org: the CTO at the root, managers in between, and
// teams at the bottom, which own the apps.
type Node struct {
	Name string
	// Role is the node's layer: cto, evp, svp, vp, director, em or team.
	Role     string
	Parent   *Node
	Children []*Node
	// Apps are a team's apps.
	Apps []*App
}

// IsTeam reports whether the node is a team.
func (n *Node) IsTeam() bool {
	return n.Role == "team"
}

// Path is the node's org path below the CTO, i.e. "em-1/checkout"; "" for
// the CTO.
func (n *Node) Path() string {
	var parts []string
	for x := n; x != nil && x.Parent != nil; x = x.Parent {
		parts = append(parts, x.Name)
	}

	slices.Reverse(parts)

	return strings.Join(parts, "/")
}

// PathFrom is the node's org path below ancestor, "" when it is ancestor.
func (n *Node) PathFrom(ancestor *Node) string {
	var parts []string
	for x := n; x != nil && x != ancestor; x = x.Parent {
		parts = append(parts, x.Name)
	}

	slices.Reverse(parts)

	return strings.Join(parts, "/")
}

// Unit is the node's ancestor in the layer under the CTO, or the node itself
// when it is in that layer.
func (n *Node) Unit() *Node {
	x := n
	for x.Parent != nil && x.Parent.Parent != nil {
		x = x.Parent
	}

	return x
}

// Teams returns the teams at or under the node, left to right.
func (n *Node) Teams() []*Node {
	if n.IsTeam() {
		return []*Node{n}
	}

	var ts []*Node
	for _, c := range n.Children {
		ts = append(ts, c.Teams()...)
	}

	return ts
}

// managerRoles names the manager layers, from the one above the teams up.
var managerRoles = []string{"em", "director", "vp", "svp", "evp"}

// weighted is a name and how common it is, relative to the others in its
// list.
type weighted struct {
	name   string
	weight int
}

// mainRoles name a team's main app after its capability, by the qualifier in
// the team's name: a search-web team runs search-ui. A team without a
// qualifier takes one of unqualifiedRoles, mostly payments-api.
var mainRoles = map[string]string{
	"web":          "ui",
	"api":          "api",
	"mobile":       "bff",
	"platform":     "platform",
	"data":         "pipeline",
	"ops":          "ops",
	"integrations": "connector",
	"experience":   "experience",
}

var unqualifiedRoles = []weighted{
	{"api", 50}, {"service", 35}, {"backend", 10}, {"core", 5},
}

// supportApps are the other apps a team runs, named for what they do rather
// than for the team, weighted by how often teams have one. The weights are a
// judgement of what's common, not measured.
var supportApps = []weighted{
	{"worker", 12}, {"sync", 9}, {"scheduler", 8}, {"consumer", 7}, {"notifier", 7},
	{"emailer", 6}, {"webhooks", 6}, {"admin", 6}, {"cron", 6}, {"importer", 5},
	{"exporter", 5}, {"queue-worker", 5}, {"reports", 5}, {"batch", 4}, {"gateway", 4},
	{"dashboard", 3}, {"proxy", 3}, {"indexer", 3}, {"etl", 3}, {"cache-warmer", 3},
	{"reconciler", 3}, {"migrator", 3}, {"support-tool", 3}, {"dispatcher", 2},
	{"poller", 2}, {"backfill", 2}, {"archiver", 2}, {"auditor", 1}, {"pdf-renderer", 1},
	{"sftp-bridge", 1},
}

// SupportAppNames are the names a team's supporting apps can have, most
// common first.
func SupportAppNames() []string {
	var out []string
	for _, w := range supportApps {
		out = append(out, w.name)
	}

	return out
}

// pickWeighted returns n of the names, chosen at random in proportion to
// their weights, without repeats.
func pickWeighted(r *rand.Rand, from []weighted, n int) []string {
	left := slices.Clone(from)

	var out []string
	for len(out) < n && len(left) > 0 {
		total := 0
		for _, w := range left {
			total += w.weight
		}

		x := r.IntN(total)
		for i, w := range left {
			if x < w.weight {
				out = append(out, w.name)
				left = slices.Delete(left, i, i+1)

				break
			}

			x -= w.weight
		}
	}

	return out
}

// capability splits a team's name into its capability and qualifier, i.e.
// search-web into search and web.
func capability(team string) (string, string) {
	for _, q := range qualifiers {
		if base, ok := strings.CutSuffix(team, "-"+q); ok {
			return base, q
		}
	}

	return team, ""
}

// buildOrg builds the org for apps apps: enough teams to run them, and
// layers of managers above, Span reports each, up to a single CTO, named
// from the industry's taxonomy. The apps are created on the teams,
// AppsPerTeam each, left to right.
func buildOrg(r *rand.Rand, apps int, t Taxonomy) (*Node, []*App) {
	teams := (apps + AppsPerTeam - 1) / AppsPerTeam

	var level []*Node
	for range teams {
		level = append(level, &Node{Role: "team"})
	}

	all := level

	// managers, layer by layer, until one is left: the CTO
	var root *Node
	for layer := 0; root == nil; layer++ {
		if len(level) == 1 && !level[0].IsTeam() {
			root = level[0]
			root.Name, root.Role = "cto", "cto"

			break
		}

		role := fmt.Sprintf("layer-%d", layer+1)
		if layer < len(managerRoles) {
			role = managerRoles[layer]
		}

		var up []*Node
		for i := 0; i < len(level); i += Span {
			m := &Node{Role: role}
			for _, c := range level[i:min(i+Span, len(level))] {
				c.Parent = m
				m.Children = append(m.Children, c)
			}

			up = append(up, m)
		}

		level = up
	}

	nameOrg(root, t)

	// the apps, AppsPerTeam per team, the last team taking what's left: the
	// team's main app, named after its capability, then supporting apps
	var out []*App
	for i, team := range all {
		n := min(AppsPerTeam, apps-i*AppsPerTeam)

		base, q := capability(team.Name)

		role := mainRoles[q]
		if q == "" {
			role = pickWeighted(r, unqualifiedRoles, 1)[0]
		}

		main := base + "-" + role
		if strings.HasSuffix(base, "-"+role) {
			main = base // broker-api, not broker-api-api
		}

		names := append([]string{main}, pickWeighted(r, supportApps, AppsPerTeam)...)

		for j := range n {
			a := &App{Name: names[j], Team: team}
			team.Apps = append(team.Apps, a)
			out = append(out, a)
		}
	}

	// app names are only unique within their team: several teams can each
	// have a worker, told apart by where they sit. Where an app's name has to
	// be unique, because it names a namespace, place gives it its team.
	return root, out
}
