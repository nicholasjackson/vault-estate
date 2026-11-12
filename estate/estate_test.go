package estate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// load builds the one cluster block in text.
func load(t *testing.T, text string) *Plan {
	t.Helper()

	p, err := build(t, text)
	require.NoError(t, err)

	return p
}

func build(t *testing.T, text string) (*Plan, error) {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cluster.xcl"), []byte(text), 0o600))

	cfgs, err := Load(dir)
	require.NoError(t, err)
	require.Len(t, cfgs, 1)

	return Build(cfgs[0])
}

// mounts returns the plan's mounts by cluster:namespace:mount.
func mounts(p *Plan) map[string]*Mount {
	out := map[string]*Mount{}
	for _, c := range p.Clusters {
		for _, ns := range c.Namespaces {
			for _, m := range ns.Mounts {
				out[c.Name+":"+ns.Path+":"+m.Path] = m
			}
		}
	}

	return out
}

// secretsPerApp is how many secrets an app has in each environment.
func secretsPerApp(a *App) int {
	n := 0
	for _, t := range a.Things() {
		n += len(t.Secrets)
	}

	return n
}

func join(parts ...string) string {
	return strings.Join(parts, "/")
}

func TestNOTHSTemplate(t *testing.T) {
	cfgs, err := Load("../examples/noths.xcl")
	require.NoError(t, err)
	require.Len(t, cfgs, 1)

	cfg := cfgs[0]
	require.Equal(t, "noths", cfg.Name())
	require.Equal(t, []string{"original", "newer"}, []string{cfg.Models[0].Name, cfg.Models[1].Name})
	require.Equal(t, map[string]string{"vm": "50%", "legacy": "40%", "kubernetes": "10%"}, cfg.Models[0].Platforms)

	// the Vault settings the template shows
	require.True(t, cfg.Identity)
	require.Equal(t, map[string]string{"legacy": "100%"}, cfg.Models[0].Policies)
	require.Nil(t, cfg.Models[0].KubernetesClusters, "the original model keeps the defaults")
	require.Equal(t, 2, *cfg.Models[1].KubernetesClusters)
	require.Equal(t, 2, *cfg.Models[1].AWSAccounts)
	require.Equal(t, "per-account", cfg.Models[1].AWSMounts)
	require.Equal(t, map[string]string{"templated": "100%"}, cfg.Models[1].Policies)

	p, err := Build(cfg)
	require.NoError(t, err)

	require.Len(t, p.Apps, 20)
	require.Len(t, p.Org.Teams(), 7)
	require.Equal(t, 2, p.Depth(), "em-N/team")
	require.Len(t, p.Clusters, 1)
	require.Len(t, p.Clusters[0].Namespaces, 1, "community: the root only")

	ms := mounts(p)
	require.Len(t, ms, 2)

	// the original: team prefixes, the environment after the app
	for _, s := range ms["noths::secret"].Secrets {
		require.Equal(t, "original", s.App.Model)
		require.Equal(t, join(s.App.Team.Path(), s.App.Name, s.Env, s.Thing, s.Name), s.Path())
	}

	// what came later: environment first, in a mount of its own
	for _, s := range ms["noths::secret-newer"].Secrets {
		require.Equal(t, "newer", s.App.Model)
		require.Equal(t, join(s.Env, s.App.Team.Path(), s.App.Name, s.Thing, s.Name), s.Path())
	}

	require.Len(t, ms["noths::secret"].Apps(), 14)
	require.Len(t, ms["noths::secret-newer"].Apps(), 6)

	want := 0
	for _, a := range p.Apps {
		want += secretsPerApp(a) * 3
	}

	require.Equal(t, want, p.Secrets())
}

// TestEveryCustomerBuilds keeps the example customers in examples
// valid, and checks each is the shape its description says.
func TestEveryCustomerBuilds(t *testing.T) {
	cfgs, err := Load("../examples")
	require.NoError(t, err)

	shapes := map[string]struct {
		edition          string
		models, clusters int
	}{
		"startup":      {edition: "community", models: 1, clusters: 1},
		"noths":        {edition: "community", models: 2, clusters: 1},
		"scaleup":      {edition: "community", models: 2, clusters: 4},
		"bank":         {edition: "enterprise", models: 1, clusters: 1},
		"retail-group": {edition: "enterprise", models: 5, clusters: 1},
	}

	var names []string
	for _, cfg := range cfgs {
		names = append(names, cfg.Name())

		p, err := Build(cfg)
		require.NoError(t, err, cfg.Name())

		want, ok := shapes[cfg.Name()]
		require.True(t, ok, "add %s to this test", cfg.Name())
		require.Equal(t, want.edition, p.Edition, cfg.Name())
		require.Len(t, p.Models, want.models, cfg.Name())
		require.Len(t, p.Clusters, want.clusters, cfg.Name())

		var b bytes.Buffer
		require.NoError(t, Render(&b, p, RenderOptions{Level: "mount", Plain: true}), cfg.Name())
	}

	require.ElementsMatch(t, []string{"startup", "noths", "scaleup", "bank", "retail-group"}, names)
}

func TestOrgFollowsTheAppCount(t *testing.T) {
	tests := []struct {
		apps, teams, depth int
	}{
		{apps: 1, teams: 1, depth: 1},
		{apps: 10, teams: 4, depth: 1},
		{apps: 20, teams: 7, depth: 2},
		{apps: 200, teams: 67, depth: 4},
		{apps: 5000, teams: 1667, depth: 6},
	}

	for _, tt := range tests {
		p := load(t, `
cluster "c" {
  model "m" {
    apps = `+strconv.Itoa(tt.apps)+`
    platforms = { kubernetes = "100%" }
  }
}
`)

		require.Len(t, p.Apps, tt.apps)
		require.Len(t, p.Org.Teams(), tt.teams, "%d apps", tt.apps)
		require.Equal(t, tt.depth, p.Depth(), "%d apps", tt.apps)
		require.Equal(t, "cto", p.Org.Role)

		var walk func(n *Node)
		walk = func(n *Node) {
			require.LessOrEqual(t, len(n.Children), Span, n.Path())

			if n.IsTeam() {
				require.LessOrEqual(t, len(n.Apps), AppsPerTeam)
				require.NotEmpty(t, n.Apps)
			}

			for _, c := range n.Children {
				walk(c)
			}
		}

		walk(p.Org)

		names := map[string]bool{}
		for _, a := range p.Apps {
			key := a.Team.Path() + "/" + a.Name
			require.False(t, names[key], "app names are unique within a team: %s", key)
			names[key] = true
		}
	}
}

func TestTeamsAreNamedFromTheIndustry(t *testing.T) {
	org := func(industry string, apps int) *Plan {
		return load(t, `
cluster "c" {
  industry = "`+industry+`"

  model "m" {
    apps      = `+strconv.Itoa(apps)+`
    platforms = { kubernetes = "100%" }
  }
}
`)
	}

	t.Run("depth 1: teams are capabilities", func(t *testing.T) {
		p := org("saas", 9)
		require.Equal(t, 1, p.Depth())

		all := Industries["saas"].capabilities()
		for _, team := range p.Org.Teams() {
			require.Contains(t, all, team.Name)
		}
	})

	t.Run("depth 2: units are domains, teams their capabilities", func(t *testing.T) {
		p := org("retail", 20)
		require.Equal(t, 2, p.Depth())

		for i, unit := range p.Org.Children {
			domain := Industries["retail"].Domains[i]
			require.Equal(t, domain.Name, unit.Name)

			for _, team := range unit.Teams() {
				require.Contains(t, domain.capabilities(), team.Name)
			}
		}
	})

	t.Run("depth 3: then areas, teams the area's capabilities", func(t *testing.T) {
		p := org("fintech", 120)
		require.Equal(t, 3, p.Depth())
		require.Equal(t, []string{"payments", "lending", "platform"}, names(p.Org.Children))

		for _, area := range p.Org.Children[0].Children {
			var caps []string
			for _, a := range Industries["fintech"].Domains[0].Areas {
				if a.Name == area.Name {
					caps = a.Capabilities
				}
			}

			require.NotEmpty(t, caps, area.Name)

			for _, team := range area.Teams() {
				require.Contains(t, pool(caps, 100), team.Name)
			}
		}
	})

	t.Run("depth 4: capability managers, capability-qualifier teams", func(t *testing.T) {
		p := org("banking", 600)
		require.Equal(t, 4, p.Depth())
		require.Equal(t, []string{"retail-banking", "wealth", "corporate-banking", "enterprise"}, names(p.Org.Children))

		for _, team := range p.Org.Teams() {
			require.True(t, strings.HasPrefix(team.Name, team.Parent.Name+"-"), team.Path())
		}
	})

	t.Run("names stay unique at any size", func(t *testing.T) {
		for _, industry := range IndustryNames() {
			p := org(industry, 5000)

			seen := map[string]bool{}
			for _, team := range p.Org.Teams() {
				require.False(t, seen[team.Path()], team.Path())
				seen[team.Path()] = true
			}

			apps := map[string]bool{}
			for _, a := range p.Apps {
				key := a.Team.Path() + "/" + a.Name
				require.False(t, apps[key], "app names are unique within a team: %s", key)
				apps[key] = true

				parts := strings.Split(a.Name, "-")
				if len(parts) > 1 {
					require.NotEqual(t, parts[len(parts)-1], parts[len(parts)-2], "doubled suffix: %s", a.Name)
				}
			}
		}
	})
}

func TestAppsAreNamedForWhatTheyDo(t *testing.T) {
	p := load(t, `
cluster "c" {
  industry = "retail"

  model "m" {
    apps      = 600
    platforms = { kubernetes = "100%" }
  }
}
`)

	var support []string
	for _, w := range supportApps {
		support = append(support, w.name)
	}

	counts := map[string]int{}
	for _, team := range p.Org.Teams() {
		base, _ := capability(team.Name)

		// the team's main app is named after its capability
		require.True(t, strings.HasPrefix(team.Apps[0].Name, base), "%s runs %s", team.Name, team.Apps[0].Name)

		// the rest are named for what they do, without the team
		for _, a := range team.Apps[1:] {
			require.Contains(t, support, a.Name)
			counts[a.Name]++
		}
	}

	// popular names turn up more often than rare ones
	require.Greater(t, counts["worker"], counts["auditor"])
	require.Greater(t, counts["sync"], counts["sftp-bridge"])
}

func TestOnlyClashingAppNamespacesGetTheTeam(t *testing.T) {
	p := load(t, `
cluster "c" {
  edition = "enterprise"

  model "m" {
    apps      = 300
    namespace = "per-app"
    platforms = { kubernetes = "100%" }
  }
}
`)

	seen := map[string]bool{}
	prefixed := 0
	for _, a := range p.Apps {
		require.False(t, seen[a.Namespace], "namespaces are unique: %s", a.Namespace)
		seen[a.Namespace] = true

		if a.Namespace != a.Name {
			require.True(t, strings.HasPrefix(a.Namespace, a.Team.Name+"-"), a.Namespace)
			prefixed++
		}
	}

	require.Positive(t, prefixed, "100 teams share worker, sync and the rest")
	require.Less(t, prefixed, len(p.Apps), "the first of each name keeps it")

	// in a shared mount the team folder tells them apart: no prefixes
	shared := load(t, `
cluster "c" {
  model "m" {
    apps      = 300
    platforms = { kubernetes = "100%" }
  }
}
`)

	for _, a := range shared.Apps {
		require.Empty(t, a.Namespace)
	}
}

// TestNoTwoSecretsShareAPath checks the one thing Vault insists on: no two
// secrets at the same path, across every customer and every combination of
// edition, industry, namespace and env, at several sizes and seeds.
func TestNoTwoSecretsShareAPath(t *testing.T) {
	check := func(t *testing.T, p *Plan) {
		t.Helper()

		seen := map[string]string{}
		for _, c := range p.Clusters {
			for _, ns := range c.Namespaces {
				for _, m := range ns.Mounts {
					for _, s := range m.Secrets {
						key := c.Name + "|" + ns.Path + "|" + m.Path + "|" + s.Path()
						owner := s.App.Team.Path() + "/" + s.App.Name

						if other, ok := seen[key]; ok {
							require.Failf(t, "two secrets share a path", "%s: %s and %s", key, other, owner)
						}

						seen[key] = owner
					}
				}
			}
		}
	}

	cfgs, err := Load("../examples")
	require.NoError(t, err)

	for _, cfg := range cfgs {
		p, err := Build(cfg)
		require.NoError(t, err)
		check(t, p)
	}

	// every namespace and env as two models side by side, so layers meet in
	// the same namespaces and teams are split between them
	for _, edition := range []string{EditionCommunity, EditionEnterprise} {
		for _, industry := range IndustryNames() {
			for _, apps := range []int{5, 40, 400} {
				for _, seed := range []int{1, 2} {
					for _, ns := range Namespaces {
						for _, env := range Envs {
							text := `
cluster "c" {
  edition  = "` + edition + `"
  industry = "` + industry + `"
  seed     = ` + strconv.Itoa(seed) + `

  model "a" {
    apps      = ` + strconv.Itoa(apps) + `
    namespace = "` + ns + `"
    env       = "` + env + `"
    platforms = { kubernetes = "100%" }
    databases = "50%"
  }

  model "b" {
    apps      = ` + strconv.Itoa(apps) + `
    namespace = "` + Namespaces[(slices.Index(Namespaces, ns)+1)%len(Namespaces)] + `"
    env       = "` + Envs[(slices.Index(Envs, env)+1)%len(Envs)] + `"
    platforms = { kubernetes = "100%" }
  }
}
`
							check(t, load(t, text))
						}
					}
				}
			}
		}
	}
}

func TestAccess(t *testing.T) {
	p := load(t, `
cluster "c" {
  industry = "retail"

  model "m" {
    apps      = 20
    platforms = { kubernetes = "100%" }
    databases = "100%"
  }
}
`)

	// 20 apps: 7 teams under two managers, so the first team's group is
	// named after its manager, not its unit
	a := p.Apps[0]
	group := a.Team.Parent.Name
	require.Equal(t, "em", a.Team.Parent.Role)
	require.Equal(t, p.Group(a.Team).Name, group)

	want := map[string][]Grant{
		"config/settings": {
			{WhoApp, a.Name, read},
			{WhoDevelopers, a.Team.Name + "-developers", readWrite},
			{WhoTesters, a.Team.Name + "-testers", read},
			{WhoManagers, group + "-manager", read},
			{WhoOps, group + "-ops", read},
		},
		"api/key": {
			{WhoApp, a.Name, read},
			{WhoDevelopers, a.Team.Name + "-developers", readWrite},
			{WhoTesters, a.Team.Name + "-testers", read},
			{WhoManagers, group + "-manager", read},
		},
		"db/read": {
			{WhoDevelopers, a.Team.Name + "-developers", read},
			{WhoManagers, group + "-manager", read},
			{WhoOps, group + "-ops", readWrite},
		},
		"db/read-write": {
			{WhoApp, a.Name, read},
			{WhoManagers, group + "-manager", read},
			{WhoOps, group + "-ops", readWrite},
		},
		"db/admin": {
			{WhoManagers, group + "-manager", read},
			{WhoOps, group + "-ops", readWrite},
		},
	}

	got := map[string][]Grant{}
	for _, m := range mounts(p) {
		for _, s := range m.Secrets {
			if s.App == a && s.Env == "dev" {
				got[s.Thing+"/"+s.Name] = s.Grants()
			}
		}
	}

	require.Equal(t, want, got)

	// every secret an app has has a rule
	for _, th := range a.Things() {
		for _, name := range th.Secrets {
			require.Contains(t, AccessRules, th.Name+"/"+name)
		}
	}
}

func TestPickWeighted(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))

	got := pickWeighted(r, []weighted{{"a", 1}, {"b", 1}, {"c", 1}}, 3)
	require.ElementsMatch(t, []string{"a", "b", "c"}, got, "no repeats")

	require.Len(t, pickWeighted(r, []weighted{{"a", 1}}, 5), 1, "no more than there are")

	counts := map[string]int{}
	for range 2000 {
		counts[pickWeighted(r, []weighted{{"common", 9}, {"rare", 1}}, 1)[0]]++
	}

	require.Greater(t, counts["common"], 1600)
}

func TestEveryTaxonomyHasEnoughDomainsAndAreas(t *testing.T) {
	for industry, tax := range Industries {
		require.GreaterOrEqual(t, len(tax.Domains), Span, industry)

		seen := map[string]bool{}
		for _, d := range tax.Domains[:Span] {
			require.GreaterOrEqual(t, len(d.Areas), Span, "%s %s", industry, d.Name)

			for _, a := range d.Areas {
				require.NotEmpty(t, a.Capabilities, "%s %s %s", industry, d.Name, a.Name)

				for _, c := range a.Capabilities {
					require.False(t, seen[c], "%s: %s is in two areas", industry, c)
					seen[c] = true
				}
			}
		}
	}
}

func names(ns []*Node) []string {
	var out []string
	for _, n := range ns {
		out = append(out, n.Name)
	}

	return out
}

func TestPlatformsAndDatabasesAreExact(t *testing.T) {
	p := load(t, `
cluster "c" {
  model "old" {
    apps      = 20
    platforms = { vm = "50%", legacy = "30%", kubernetes = "20%" }
    databases = "30%"
  }

  model "new" {
    apps = 10
    platforms = { kubernetes = "100%" }
  }
}
`)

	got := map[string]map[string]int{}
	dbs := map[string]int{}
	for _, a := range p.Apps {
		if got[a.Model] == nil {
			got[a.Model] = map[string]int{}
		}

		got[a.Model][a.Platform]++

		if a.Database {
			dbs[a.Model]++
		}
	}

	require.Equal(t, map[string]int{"vm": 10, "legacy": 6, "kubernetes": 4}, got["old"])
	require.Equal(t, map[string]int{"kubernetes": 10}, got["new"])
	require.Equal(t, map[string]int{"old": 6}, dbs, "a model without databases has none")
}

func TestApportionAlwaysAddsUp(t *testing.T) {
	for n := range 50 {
		parts := apportion(n, []int{40, 30, 10, 20})

		total := 0
		for _, x := range parts {
			total += x
		}

		require.Equal(t, n, total)
	}

	require.Equal(t, []int{1, 1, 1}, apportion(3, []int{1, 1, 1}))
	require.Equal(t, []int{7, 6, 1}, apportion(14, []int{50, 40, 10}))
}

func TestModelsTakeTheAppsInOrder(t *testing.T) {
	p := load(t, `
cluster "c" {
  model "first" {
    apps = 5
    platforms = { kubernetes = "100%" }
  }

  model "second" {
    apps = 4
    platforms = { kubernetes = "100%" }
  }
}
`)

	for i, a := range p.Apps {
		want := "first"
		if i >= 5 {
			want = "second"
		}

		require.Equal(t, want, a.Model, a.Name)
	}

	// both lay out secrets in the root namespace; the later one gets a mount
	// of its own
	ms := mounts(p)
	require.Equal(t, "first", ms["c::secret"].Model)
	require.Equal(t, "second", ms["c::secret-second"].Model)
}

// TestPaths covers the architect's shapes: where the namespaces sit, and
// where the environment goes, decide the path.
func TestPaths(t *testing.T) {
	tests := []struct {
		namespace, env string
		ns             func(s Secret) string
		path           func(s Secret) string
		envs           int
	}{
		{
			namespace: "none", env: "after-app",
			ns:   func(Secret) string { return "" },
			path: func(s Secret) string { return join(s.App.Team.Path(), s.App.Name, s.Env, s.Thing, s.Name) },
			envs: 3,
		},
		{
			namespace: "none", env: "first",
			ns:   func(Secret) string { return "" },
			path: func(s Secret) string { return join(s.Env, s.App.Team.Path(), s.App.Name, s.Thing, s.Name) },
			envs: 3,
		},
		{
			namespace: "none", env: "none",
			ns:   func(Secret) string { return "" },
			path: func(s Secret) string { return join(s.App.Team.Path(), s.App.Name, s.Thing, s.Name) },
			envs: 1,
		},
		{
			namespace: "per-unit", env: "none",
			ns:   func(s Secret) string { return s.App.Team.Unit().Name },
			path: func(s Secret) string { return join(s.App.Team.Name, s.App.Name, s.Thing, s.Name) },
			envs: 1,
		},
		{
			namespace: "per-unit", env: "first",
			ns:   func(s Secret) string { return s.App.Team.Unit().Name },
			path: func(s Secret) string { return join(s.Env, s.App.Team.Name, s.App.Name, s.Thing, s.Name) },
			envs: 3,
		},
		{
			namespace: "per-unit", env: "after-app",
			ns:   func(s Secret) string { return s.App.Team.Unit().Name },
			path: func(s Secret) string { return join(s.App.Team.Name, s.App.Name, s.Env, s.Thing, s.Name) },
			envs: 3,
		},
		{
			namespace: "per-app", env: "first",
			ns:   func(s Secret) string { return s.App.Namespace },
			path: func(s Secret) string { return join(s.Env, s.Thing, s.Name) },
			envs: 3,
		},
		{
			namespace: "per-app", env: "none",
			ns:   func(s Secret) string { return s.App.Namespace },
			path: func(s Secret) string { return join(s.Thing, s.Name) },
			envs: 1,
		},
		{
			namespace: "per-unit/per-app", env: "after-app",
			ns:   func(s Secret) string { return s.App.Team.Unit().Name + "/" + s.App.Namespace },
			path: func(s Secret) string { return join(s.Env, s.Thing, s.Name) },
			envs: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.namespace+" "+tt.env, func(t *testing.T) {
			p := load(t, `
cluster "c" {
  edition = "enterprise"

  model "m" {
    apps      = 40
    namespace = "`+tt.namespace+`"
    env       = "`+tt.env+`"
    databases = "50%"
    platforms = { kubernetes = "100%" }
  }
}
`)

			require.Equal(t, 2, p.Depth(), "units are the EMs, teams under them")
			require.Len(t, p.Clusters, 1)

			seen := 0
			for _, ns := range p.Clusters[0].Namespaces {
				for _, m := range ns.Mounts {
					require.Equal(t, "secret", m.Path)

					for _, s := range m.Secrets {
						require.Equal(t, tt.ns(s), ns.Path, s.Path())
						require.Equal(t, tt.path(s), s.Path())
						seen++
					}
				}
			}

			want := 0
			for _, a := range p.Apps {
				want += secretsPerApp(a) * tt.envs
			}

			require.Equal(t, want, seen)
		})
	}
}

func TestCommunityHasClustersForNamespaces(t *testing.T) {
	p := load(t, `
cluster "c" {
  model "old" {
    apps = 14
    platforms = { kubernetes = "100%" }
  }

  model "units" {
    apps      = 12
    namespace = "per-unit"
    platforms = { kubernetes = "100%" }
  }

  model "apps" {
    apps      = 2
    namespace = "per-unit/per-app"
    platforms = { kubernetes = "100%" }
  }
}
`)

	require.Equal(t, "c", p.Clusters[0].Name, "the cluster block's own cluster first")

	for _, c := range p.Clusters {
		require.Len(t, c.Namespaces, 1, "%s: community has only root", c.Name)

		for _, m := range c.Namespaces[0].Mounts {
			for _, a := range m.Apps() {
				switch a.Model {
				case "old":
					require.Equal(t, "c", c.Name)
				case "units":
					require.Equal(t, "c-"+a.Team.Unit().Name, c.Name)
				case "apps":
					require.Equal(t, "c-"+a.Team.Unit().Name+"-"+a.Namespace, c.Name)
				}
			}
		}
	}
}

func TestNestedNamespacesHaveTheirParents(t *testing.T) {
	p := load(t, `
cluster "c" {
  edition = "enterprise"

  model "m" {
    apps      = 3
    namespace = "per-unit/per-app"
    platforms = { kubernetes = "100%" }
  }
}
`)

	var paths []string
	for _, ns := range p.Clusters[0].Namespaces {
		paths = append(paths, ns.Path)
	}

	require.Equal(t, "", paths[0], "root first")

	for _, path := range paths[1:] {
		if i := strings.LastIndex(path, "/"); i > 0 {
			require.Contains(t, paths, path[:i], "the parent of %s", path)
		}
	}
}

func TestDeterministic(t *testing.T) {
	text := func(seed int) string {
		return `
cluster "c" {
  seed      = ` + strconv.Itoa(seed) + `

  model "m" {
    apps      = 30
    databases = "50%"
    platforms = { kubernetes = "100%" }
  }
}
`
	}

	render := func(p *Plan) string {
		var b bytes.Buffer
		require.NoError(t, Render(&b, p, RenderOptions{Plain: true}))

		return b.String()
	}

	a, b, c := render(load(t, text(7))), render(load(t, text(7))), render(load(t, text(8)))
	require.Equal(t, a, b)
	require.NotEqual(t, a, c)
}

func TestRender(t *testing.T) {
	p := load(t, `
cluster "c" {
  edition = "enterprise"

  model "old" {
    apps      = 3
    databases = "100%"
    platforms = { kubernetes = "100%" }
  }

  model "new" {
    apps      = 3
    namespace = "per-app"
    platforms = { kubernetes = "100%" }
  }
}
`)

	out := func(level string) string {
		var b bytes.Buffer
		require.NoError(t, Render(&b, p, RenderOptions{Level: level, Plain: true}))

		// the tree, without the header and its legend
		return b.String()[strings.Index(b.String(), "\n\n")+2:]
	}

	full := out("")
	require.Contains(t, full, glyphCluster+" cluster c")
	require.Contains(t, full, glyphNamespace+" root")
	require.Contains(t, full, glyphMount+" secret/")
	require.Contains(t, full, glyphFolder+" db/")
	require.Contains(t, full, glyphTeam+" "+p.Apps[0].Team.Name+"/")
	require.Contains(t, full, glyphSecret+" admin  managers r · ops rw")
	require.Contains(t, full, glyphSecret+" settings  app r · developers rw · testers r · managers r · ops r")
	require.Contains(t, full, glyphSecret+" key  app r · developers rw · testers r · managers r\n")
	require.NotContains(t, full, "\x1b[", "plain has no colour")

	// an app with a namespace of its own is named on its mount
	require.Contains(t, full, glyphApp+" "+p.Apps[5].Name+" of "+p.Apps[5].Team.Name+" on ")

	// each level stops where it says
	require.NotContains(t, out("namespace"), glyphMount)
	require.Contains(t, out("mount"), glyphMount)
	require.NotContains(t, out("mount"), glyphApp+" "+p.Apps[0].Name+"/")
	require.Contains(t, out("app"), glyphApp+" "+p.Apps[0].Name+"/")
	require.NotContains(t, out("app"), glyphSecret)

	var b bytes.Buffer
	require.ErrorContains(t, Render(&b, p, RenderOptions{Level: "everything"}), "unknown level")

	// a community cluster has no namespaces to show
	ce := load(t, `
cluster "c" {
  model "m" {
    apps = 3
    platforms = { kubernetes = "100%" }
  }
}
`)

	b.Reset()
	require.NoError(t, Render(&b, ce, RenderOptions{Plain: true}))
	require.NotContains(t, b.String()[strings.Index(b.String(), "\n\n")+2:], glyphNamespace)
}

func TestRenderJSON(t *testing.T) {
	p := load(t, `
cluster "c" {
  edition = "enterprise"

  model "old" {
    apps      = 3
    databases = "100%"
    platforms = { kubernetes = "100%" }
  }

  model "new" {
    apps      = 3
    namespace = "per-app"
    platforms = { kubernetes = "100%" }
  }
}
`)

	out := func(level string) jsonPlan {
		var b bytes.Buffer
		require.NoError(t, RenderJSON(&b, p, RenderOptions{Level: level}))

		var jp jsonPlan
		require.NoError(t, json.Unmarshal(b.Bytes(), &jp))

		return jp
	}

	full := out("")
	require.Equal(t, "c", full.Name)
	require.Equal(t, p.Secrets(), full.Summary.Secrets)
	require.Len(t, full.Apps, 6)
	require.Equal(t, p.Apps[5].Namespace, full.Apps[5].Namespace)
	require.Equal(t, "cto", full.Org.Role)
	require.Len(t, full.Models, 2)

	// every secret is there, with its path and grants
	var secrets []jsonSecret
	for _, c := range full.Clusters {
		for _, ns := range c.Namespaces {
			for _, m := range ns.Mounts {
				secrets = append(secrets, m.Secrets...)
			}
		}
	}

	require.Len(t, secrets, p.Secrets())

	first := mounts(p)["c::secret"].Secrets[0]
	require.Equal(t, first.Path(), secrets[0].Path)
	require.Equal(t, first.Segments(), secrets[0].Segments)
	require.Len(t, secrets[0].Grants, len(first.Grants()))

	// each level stops where it says
	for _, ns := range out("namespace").Clusters[0].Namespaces {
		require.Empty(t, ns.Mounts)
	}

	for _, ns := range out("mount").Clusters[0].Namespaces {
		for _, m := range ns.Mounts {
			require.NotEmpty(t, m.Apps)
			require.Empty(t, m.Secrets)
		}
	}

	var b bytes.Buffer
	require.ErrorContains(t, RenderJSON(&b, p, RenderOptions{Level: "everything"}), "unknown level")
}

func TestInvalid(t *testing.T) {
	tests := map[string]struct {
		cluster, model, extra, want string
	}{
		"edition":     {cluster: `edition = "pro"`, want: "unknown edition"},
		"industry":    {cluster: `industry = "mining"`, want: "unknown industry"},
		"databases":   {model: `databases = "120%"`, want: "from 0% to 100%"},
		"no percent":  {model: `databases = "50"`, want: "not a percentage"},
		"short":       {model: `platforms = { kubernetes = "60%", vm = "30%" }`, want: "add up to 90%, not 100%"},
		"namespace":   {model: `namespace = "per-galaxy"`, want: "unknown namespace"},
		"env":         {model: `env = "last"`, want: "unknown env"},
		"apps":        {model: `apps = 0`, want: "apps must be at least 1"},
		"no platform": {model: `platforms = { vm = "0%" }`, want: "add up to 0%, not 100%"},

		"zero k8s clusters": {model: `kubernetes_clusters = 0`, want: "model m: kubernetes_clusters must be at least 1"},
		"negative k8s":      {model: `kubernetes_clusters = -2`, want: "model m: kubernetes_clusters must be at least 1"},
		"zero aws accounts": {model: `aws_accounts = 0`, want: "model m: aws_accounts must be at least 1"},
		"aws mounts":        {model: `aws_mounts = "per-region"`, want: `model m: unknown aws_mounts "per-region", use one of [shared per-account]`},
		"policy style":      {model: `policies = { bespoke = "100%" }`, want: `model m: unknown policy style "bespoke", use one of [per-app templated legacy]`},
		"policy short":      {model: `policies = { per-app = "60%", legacy = "30%" }`, want: "model m: policies add up to 90%, not 100%"},
		"policy percent":    {model: `policies = { per-app = "all" }`, want: "model m: policy style per-app: \"all\" is not a percentage"},
		"user auth":         {model: `user_auth = "team"`, want: `model m: unknown user_auth "team", use one of [root unit]`},
		"user auth unit":    {model: `user_auth = "unit"`, want: `model m: user_auth "unit" needs a namespace per unit`},
		"unit per-app":      {model: `namespace = "per-app"`, extra: `user_auth = "unit"`, want: `model m: user_auth "unit" needs a namespace per unit`},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			model := map[string]string{"apps": "apps = 3", "platforms": `platforms = { kubernetes = "100%" }`}
			for _, line := range []string{tt.model, tt.extra} {
				if line != "" {
					model[strings.Fields(line)[0]] = line
				}
			}

			var lines []string
			for _, k := range []string{"apps", "namespace", "env", "platforms", "databases", "kubernetes_clusters", "aws_accounts", "aws_mounts", "policies", "user_auth"} {
				if model[k] != "" {
					lines = append(lines, "    "+model[k])
				}
			}

			_, err := build(t, "cluster \"c\" {\n  "+tt.cluster+"\n\n  model \"m\" {\n"+strings.Join(lines, "\n")+"\n  }\n}\n")
			require.ErrorContains(t, err, tt.want)
		})
	}

	_, err := Build(Config{})
	require.ErrorContains(t, err, "no models")

	// every model says where its apps run
	_, err = Build(Config{Models: []ModelConfig{{Name: "m", Apps: 1}}})
	require.ErrorContains(t, err, "say where the model's apps run")

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "c.xcl"), []byte("cluster \"c\" {\n  model \"m\" {\n    apps = 1\n  }\n}\n"), 0o600))
	_, err = Load(dir)
	require.ErrorContains(t, err, "platforms")

	k8s := map[string]string{"kubernetes": "100%"}
	dup := Config{Models: []ModelConfig{{Name: "m", Apps: 1, Platforms: k8s}, {Name: "m", Apps: 1, Platforms: k8s}}}
	_, err = Build(dup)
	require.ErrorContains(t, err, "more than once")
}

func TestNewSettingsDefault(t *testing.T) {
	p := load(t, `
cluster "c" {
  edition = "enterprise"

  model "flat" {
    apps      = 3
    platforms = { kubernetes = "100%" }
  }

  model "units" {
    apps      = 3
    namespace = "per-unit"
    platforms = { kubernetes = "100%" }
  }

  model "apps" {
    apps      = 3
    namespace = "per-app"
    platforms = { kubernetes = "100%" }
  }

  model "unit-apps" {
    apps      = 3
    namespace = "per-unit/per-app"
    platforms = { kubernetes = "100%" }
  }
}
`)

	require.False(t, p.Identity)

	userAuth := map[string]string{}
	for _, m := range p.Models {
		require.Equal(t, 1, *m.KubernetesClusters, m.Name)
		require.Equal(t, 1, *m.AWSAccounts, m.Name)
		require.Equal(t, "shared", m.AWSMounts, m.Name)

		shares, err := m.policyShares()
		require.NoError(t, err)
		require.Equal(t, map[string]int{"per-app": 10000}, shares, m.Name)

		userAuth[m.Name] = m.UserAuth
	}

	// people log in by the namespace layout: the unit where there is one,
	// the root otherwise
	require.Equal(t, map[string]string{"flat": "root", "units": "unit", "apps": "root", "unit-apps": "unit"}, userAuth)

	var b bytes.Buffer
	require.NoError(t, RenderJSON(&b, p, RenderOptions{Level: "namespace"}))

	var jp jsonPlan
	require.NoError(t, json.Unmarshal(b.Bytes(), &jp))
	require.False(t, jp.Identity)
	require.Equal(t, 1, jp.Models[0].KubernetesClusters)
	require.Equal(t, 1, jp.Models[0].AWSAccounts)
	require.Equal(t, "shared", jp.Models[0].AWSMounts)
	require.Equal(t, map[string]string{"per-app": "100%"}, jp.Models[0].Policies)
	require.Equal(t, "root", jp.Models[0].UserAuth)
	require.Equal(t, "unit", jp.Models[1].UserAuth)

	// a description built in code, without the settings, defaults the same
	k8s := map[string]string{"kubernetes": "100%"}
	p, err := Build(Config{Models: []ModelConfig{{Name: "m", Apps: 1, Platforms: k8s}}})
	require.NoError(t, err)
	require.Equal(t, 1, *p.Models[0].KubernetesClusters)
	require.Equal(t, 1, *p.Models[0].AWSAccounts)
	require.Equal(t, "shared", p.Models[0].AWSMounts)
	require.Equal(t, "root", p.Models[0].UserAuth)
}

func TestNewSettingsCarried(t *testing.T) {
	p := load(t, `
cluster "c" {
  edition  = "enterprise"
  identity = true

  model "units" {
    apps                = 6
    namespace           = "per-unit"
    platforms           = { kubernetes = "50%", lambda = "50%" }
    kubernetes_clusters = 3
    aws_accounts        = 4
    aws_mounts          = "per-account"
    policies            = { per-app = "60%", templated = "30%", legacy = "10%" }
    user_auth           = "root"
  }

  model "unit-apps" {
    apps      = 3
    namespace = "per-unit/per-app"
    platforms = { vm = "100%" }
    policies  = { legacy = "12.5%", templated = "87.5%" }
    user_auth = "unit"
  }
}
`)

	require.True(t, p.Identity)

	var b bytes.Buffer
	require.NoError(t, RenderJSON(&b, p, RenderOptions{Level: "namespace"}))

	var jp jsonPlan
	require.NoError(t, json.Unmarshal(b.Bytes(), &jp))
	require.True(t, jp.Identity)
	require.Len(t, jp.Models, 2)

	units := jp.Models[0]
	require.Equal(t, 3, units.KubernetesClusters)
	require.Equal(t, 4, units.AWSAccounts)
	require.Equal(t, "per-account", units.AWSMounts)
	require.Equal(t, map[string]string{"per-app": "60%", "templated": "30%", "legacy": "10%"}, units.Policies)
	require.Equal(t, "root", units.UserAuth)

	unitApps := jp.Models[1]
	require.Equal(t, 1, unitApps.KubernetesClusters)
	require.Equal(t, map[string]string{"legacy": "12.5%", "templated": "87.5%"}, unitApps.Policies)
	require.Equal(t, "unit", unitApps.UserAuth)

	// the raw JSON uses the description's own names
	for _, key := range []string{`"identity": true`, `"kubernetes_clusters": 3`, `"aws_accounts": 4`, `"aws_mounts": "per-account"`, `"user_auth": "root"`, `"policies": {`} {
		require.Contains(t, b.String(), key)
	}
}

// customers builds the five example customers, by name.
func customers(t *testing.T) map[string]*Plan {
	t.Helper()

	cfgs, err := Load("../examples")
	require.NoError(t, err)

	out := map[string]*Plan{}
	for _, cfg := range cfgs {
		p, err := Build(cfg)
		require.NoError(t, err, cfg.Name())

		out[cfg.Name()] = p
	}

	require.Len(t, out, 5)

	return out
}

func TestPeople(t *testing.T) {
	var devCounts []int

	for name, p := range customers(t) {
		usernames := map[string]bool{}
		for _, person := range p.People {
			require.False(t, usernames[person.Name], "%s: %s is used twice", name, person.Name)
			usernames[person.Name] = true
		}

		// every team: 2 to 8 developers, one tester, one PM, in its
		// parent's group
		for _, team := range p.Org.Teams() {
			kinds := map[string]int{}
			for _, person := range p.People {
				if person.Team == team {
					kinds[person.Kind]++
					require.Equal(t, team.Parent, person.Group.Manager, "%s: %s", name, person.Name)
				}
			}

			require.GreaterOrEqual(t, kinds[KindDeveloper], 2, "%s: %s", name, team.Name)
			require.LessOrEqual(t, kinds[KindDeveloper], 8, "%s: %s", name, team.Name)
			require.Equal(t, 1, kinds[KindTester], "%s: %s", name, team.Name)
			require.Equal(t, 1, kinds[KindPM], "%s: %s", name, team.Name)
			require.Len(t, kinds, 3, "%s: %s", name, team.Name)

			devCounts = append(devCounts, kinds[KindDeveloper])

			g := p.Group(team)
			require.NotNil(t, g)
			require.Contains(t, g.Teams, team)
		}

		// every group: one manager, two ops, up to four teams, one ops
		// manager; every team in exactly one group
		inGroups := 0
		for _, g := range p.Groups {
			require.Equal(t, g.Manager.Name, g.Name)
			require.Equal(t, g.Name+"-manager", g.ManagerPerson.Name)
			require.Equal(t, KindManager, g.ManagerPerson.Kind)
			require.Len(t, g.Ops, 2, "%s: %s", name, g.Name)
			for _, o := range g.Ops {
				require.Equal(t, KindOps, o.Kind)
				require.Equal(t, g, o.Group)
			}

			require.NotEmpty(t, g.Teams)
			require.LessOrEqual(t, len(g.Teams), 4)
			require.NotNil(t, g.OpsManager, "%s: %s", name, g.Name)
			require.Contains(t, g.OpsManager.Groups, g)

			inGroups += len(g.Teams)
		}

		require.Equal(t, len(p.Org.Teams()), inGroups, name)

		// every group under exactly one ops manager, at most four each
		seen := map[*OpsGroup]int{}
		for _, om := range p.OpsManagers {
			require.NotEmpty(t, om.Groups)
			require.LessOrEqual(t, len(om.Groups), 4, name)
			require.Equal(t, KindOpsManager, om.Person.Kind)
			require.Equal(t, om, om.Person.OpsManager)

			for _, g := range om.Groups {
				seen[g]++
			}
		}

		require.Len(t, seen, len(p.Groups), name)
		for _, n := range seen {
			require.Equal(t, 1, n)
		}
	}

	slices.Sort(devCounts)
	require.Equal(t, 6, devCounts[len(devCounts)/2], "median of %d teams", len(devCounts))
}

func TestPeopleNames(t *testing.T) {
	p := load(t, `
cluster "c" {
  model "m" {
    apps      = 3
    platforms = { kubernetes = "100%" }
  }
}
`)

	// one team, so it sits under the CTO, which names its group
	team := p.Org.Teams()[0]
	require.Len(t, p.Groups, 1)
	require.Equal(t, "cto", p.Groups[0].Name)

	var names []string
	for _, person := range p.People {
		names = append(names, person.Name)
	}

	devs := len(names) - 6
	want := []string{"cto-manager", "cto-ops-1", "cto-ops-2"}
	for i := range devs {
		want = append(want, fmt.Sprintf("%s-dev-%d", team.Name, i+1))
	}

	want = append(want, team.Name+"-tester", team.Name+"-pm", "ops-manager-1")
	require.Equal(t, want, names)
}

func TestPeopleAreDeterministic(t *testing.T) {
	text := func(seed int) string {
		return `
cluster "c" {
  seed = ` + strconv.Itoa(seed) + `

  model "m" {
    apps      = 60
    platforms = { kubernetes = "100%" }
  }
}
`
	}

	names := func(p *Plan) []string {
		var out []string
		for _, person := range p.People {
			out = append(out, person.Name)
		}

		return out
	}

	a, b, c := names(load(t, text(3))), names(load(t, text(3))), names(load(t, text(4)))
	require.Equal(t, a, b)
	require.NotEqual(t, a, c)
}

func TestPeopleLeaveTheLayoutAlone(t *testing.T) {
	// digests of each example customer's layout from before people were
	// added: people come from a stream of their own, so the org, apps,
	// platforms and secrets mustn't move
	want := map[string]string{
		"bank":         "598a5f2d375a95707a6fb3b928405a5755bb61aad236d32e6b846af6c3551a22",
		"noths":        "dd4a67f2a2f16012405b55894eebff158ae0c6b421b63fe022d2ad2dc08babeb",
		"retail-group": "67a1de4bb53bab81993c298a4a766ad88711299fdd61f0ec0d4435e610b9bcda",
		"scaleup":      "4254de7db3e8132a2c09abffe5bb3d99c693999cc258aacbdd708ed3cf327a6c",
		"startup":      "7d7dfaff5be9c05887469b26f573b83575d5dd1e352d8b391250b500990eeccd",
	}

	for name, p := range customers(t) {
		require.Equal(t, want[name], layoutDigest(p), name)
	}
}

func TestPeopleShown(t *testing.T) {
	p := load(t, `
cluster "c" {
  model "m" {
    apps      = 24
    platforms = { kubernetes = "100%" }
  }
}
`)

	var b bytes.Buffer
	require.NoError(t, RenderJSON(&b, p, RenderOptions{Level: "namespace"}))

	var jp jsonPlan
	require.NoError(t, json.Unmarshal(b.Bytes(), &jp))
	require.Equal(t, len(p.People), jp.Summary.People)
	require.Len(t, jp.People, len(p.People))
	require.Len(t, jp.Groups, 2)

	g := jp.Groups[0]
	require.Equal(t, g.Name+"-manager", g.Manager)
	require.Equal(t, []string{g.Name + "-ops-1", g.Name + "-ops-2"}, g.Ops)
	require.Len(t, g.Teams, 4)
	require.Equal(t, "ops-manager-1", g.OpsManager)

	require.Equal(t, jsonPerson{Name: g.Name + "-manager", Kind: "manager", Group: g.Name}, jp.People[0])
	require.Equal(t, jsonPerson{Name: "ops-manager-1", Kind: "ops-manager"}, jp.People[len(jp.People)-1])

	b.Reset()
	require.NoError(t, Render(&b, p, RenderOptions{Plain: true, Level: "namespace"}))
	require.Contains(t, b.String(), fmt.Sprintf("people: %d, in 2 ops groups under 1 ops manager", len(p.People)))
}

// layoutDigest is a digest of the estate's layout: its org, its apps and
// their platforms and databases, and where every secret sits. People,
// grants and anything Vault-specific are left out.
func layoutDigest(p *Plan) string {
	h := sha256.New()

	var walk func(n *Node)
	walk = func(n *Node) {
		fmt.Fprintf(h, "node %s %s %s\n", n.Role, n.Name, n.Path())
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(p.Org)

	for _, a := range p.Apps {
		fmt.Fprintf(h, "app %s %s %s %s %t %s\n", a.Team.Path(), a.Name, a.Model, a.Platform, a.Database, a.Namespace)
	}

	for _, c := range p.Clusters {
		for _, ns := range c.Namespaces {
			for _, m := range ns.Mounts {
				for _, sec := range m.Secrets {
					fmt.Fprintf(h, "secret %s %s %s %s %s\n", c.Name, ns.Path, m.Path, sec.Path(), sec.App.Name)
				}
			}
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

func TestKubernetesAndAWSSpread(t *testing.T) {
	text := func(seed int) string {
		return `
cluster "c" {
  seed = ` + strconv.Itoa(seed) + `

  model "m" {
    apps                = 30
    platforms           = { kubernetes = "40%", lambda = "40%", vm = "20%" }
    kubernetes_clusters = 3
    aws_accounts        = 4
  }

  model "small" {
    apps      = 6
    platforms = { kubernetes = "50%", lambda = "50%" }
  }
}
`
	}

	p := load(t, text(1))

	clusters, accounts := map[string]int{}, map[string]int{}
	for _, a := range p.Apps {
		switch a.Platform {
		case "kubernetes":
			require.Empty(t, a.AWSAccount, a.Name)
			clusters[a.Model+" "+a.KubeCluster]++
		case "lambda":
			require.Empty(t, a.KubeCluster, a.Name)
			require.Regexp(t, `^[1-9][0-9]{11}$`, a.AWSAccount)
			require.Contains(t, p.AWSAccounts[a.Model], a.AWSAccount)
			accounts[a.Model+" "+a.AWSAccount]++
		default:
			require.Empty(t, a.KubeCluster, a.Name)
			require.Empty(t, a.AWSAccount, a.Name)
		}
	}

	// 12 Kubernetes and 12 Lambda apps in m, dealt evenly; small's on its
	// one cluster and account
	ids := p.AWSAccounts["m"]
	require.Len(t, ids, 4)
	require.Len(t, p.AWSAccounts["small"], 1)
	require.Equal(t, map[string]int{
		"m k8s-m-1": 4, "m k8s-m-2": 4, "m k8s-m-3": 4, "small k8s-small-1": 3,
	}, clusters)
	require.Equal(t, map[string]int{
		"m " + ids[0]: 3, "m " + ids[1]: 3, "m " + ids[2]: 3, "m " + ids[3]: 3,
		"small " + p.AWSAccounts["small"][0]: 3,
	}, accounts)

	// account IDs are unique across the customer
	all := append(slices.Clone(ids), p.AWSAccounts["small"]...)
	slices.Sort(all)
	require.Len(t, slices.Compact(all), 5)

	// fewer apps than clusters: each app still on exactly one
	few := load(t, `
cluster "c" {
  model "m" {
    apps                = 2
    platforms           = { kubernetes = "100%" }
    kubernetes_clusters = 3
  }
}
`)
	seen := map[string]bool{}
	for _, a := range few.Apps {
		require.NotEmpty(t, a.KubeCluster)
		require.False(t, seen[a.KubeCluster], "dealt round-robin, so no cluster gets two of two apps")
		seen[a.KubeCluster] = true
	}

	placement := func(p *Plan) []string {
		var out []string
		for _, a := range p.Apps {
			out = append(out, a.Team.Name+"/"+a.Name+" "+a.KubeCluster+a.AWSAccount)
		}

		return out
	}

	require.Equal(t, placement(load(t, text(1))), placement(p))
	require.NotEqual(t, placement(load(t, text(2))), placement(p))
}

func TestPolicyMix(t *testing.T) {
	// a single model of n ops groups: n groups of 4 teams of 3 apps under
	// one em layer
	styles := func(groups int, policies string) map[string]int {
		p := load(t, `
cluster "c" {
  model "m" {
    apps      = `+strconv.Itoa(groups*4*3)+`
    platforms = { kubernetes = "100%" }
    `+policies+`
  }
}
`)
		require.Len(t, p.Groups, groups)

		got := map[string]int{}
		for _, g := range p.Groups {
			require.Equal(t, "m", g.Model)
			got[g.Style]++
		}

		return got
	}

	mix := `policies = { per-app = "60%", templated = "30%", legacy = "10%" }`
	require.Equal(t, map[string]int{"per-app": 6, "templated": 3, "legacy": 1}, styles(10, mix))

	seven := styles(7, mix)
	require.Equal(t, 7, seven["per-app"]+seven["templated"]+seven["legacy"])
	for style, share := range map[string]float64{"per-app": 4.2, "templated": 2.1, "legacy": 0.7} {
		require.InDelta(t, share, float64(seven[style]), 1, style)
	}

	require.Equal(t, map[string]int{"per-app": 10}, styles(10, ""))
}

func TestOneStylePerGroup(t *testing.T) {
	p := load(t, `
cluster "c" {
  model "old" {
    apps      = 54
    platforms = { vm = "100%" }
    policies  = { legacy = "50%", templated = "50%" }
  }

  model "new" {
    apps      = 42
    platforms = { kubernetes = "100%" }
    policies  = { per-app = "100%" }
  }
}
`)

	for _, g := range p.Groups {
		require.Contains(t, Styles, g.Style, g.Name)

		// the model holding most of the group's apps owns it, and its style
		// comes from that model's mix
		apps := map[string]int{}
		for _, team := range g.Teams {
			for _, a := range team.Apps {
				require.Equal(t, g, a.Group, a.Name)
				apps[a.Model]++
			}
		}

		require.GreaterOrEqual(t, apps[g.Model], apps["old"]+apps["new"]-apps[g.Model], g.Name)
		if g.Model == "new" {
			require.Equal(t, "per-app", g.Style)
		} else {
			require.Contains(t, []string{"legacy", "templated"}, g.Style)
		}
	}

	// one group of 4 teams has 6 old and 6 new apps (apps 48 to 59): a tie
	// goes to the earlier model
	tie := p.Group(p.Apps[48].Team)
	require.Equal(t, "old", tie.Model)

	var b bytes.Buffer
	require.NoError(t, RenderJSON(&b, p, RenderOptions{Level: "namespace"}))

	var jp jsonPlan
	require.NoError(t, json.Unmarshal(b.Bytes(), &jp))

	for i, g := range jp.Groups {
		require.Equal(t, p.Groups[i].Style, g.Style)
		require.Equal(t, p.Groups[i].Model, g.Model)
	}

	for i, a := range jp.Apps {
		require.Equal(t, p.Apps[i].KubeCluster, a.KubeCluster)
		require.Equal(t, p.Apps[i].Group.Name, a.Group)
	}

	require.Len(t, jp.Models[0].AWSAccountIDs, 1)
	require.Contains(t, b.String(), `"kube_cluster": "k8s-new-1"`)
}

func TestStylesAreDeterministic(t *testing.T) {
	text := func(seed int) string {
		return `
cluster "c" {
  seed = ` + strconv.Itoa(seed) + `

  model "m" {
    apps      = 240
    platforms = { kubernetes = "100%" }
    policies  = { per-app = "40%", templated = "30%", legacy = "30%" }
  }
}
`
	}

	styles := func(p *Plan) []string {
		var out []string
		for _, g := range p.Groups {
			out = append(out, g.Style)
		}

		return out
	}

	require.Equal(t, styles(load(t, text(5))), styles(load(t, text(5))))
	require.NotEqual(t, styles(load(t, text(5))), styles(load(t, text(6))))
}

func TestPersonAccess(t *testing.T) {
	p := load(t, `
cluster "c" {
  edition = "enterprise"

  model "flat" {
    apps      = 30
    databases = "50%"
    platforms = { kubernetes = "100%" }
  }

  model "apps" {
    apps      = 60
    namespace = "per-unit/per-app"
    databases = "50%"
    platforms = { vm = "100%" }
  }
}
`)

	// every secret, by where it sits
	type located struct {
		ref SecretRef
		sec Secret
	}

	var all []located
	for _, c := range p.Clusters {
		for _, ns := range c.Namespaces {
			for _, m := range ns.Mounts {
				for _, sec := range m.Secrets {
					all = append(all, located{SecretRef{c.Name, ns.Path, m.Path, sec.Path()}, sec})
				}
			}
		}
	}

	pms := map[string]bool{}
	for _, person := range p.People {
		if person.Kind == KindPM {
			pms[person.Name] = true
		}
	}

	// no grant names a PM, or any kind of principal but the five
	for _, l := range all {
		for _, g := range l.sec.Grants() {
			require.False(t, pms[g.Principal], g.Principal)
			require.Contains(t, Whos, g.Who)
		}
	}

	kinds := map[string]int{}
	for _, person := range p.People {
		kinds[person.Kind]++
		got := p.Access(person)

		switch person.Kind {
		case KindPM:
			require.Empty(t, got, person.Name)

		case KindTester:
			// read on their team's apps' configuration and API keys, nothing
			// else
			want := map[SecretRef]Ops{}
			for _, l := range all {
				if l.sec.App.Team == person.Team && (l.sec.Thing+"/"+l.sec.Name == "config/settings" || l.sec.Thing+"/"+l.sec.Name == "api/key") {
					want[l.ref] = Ops{Read: true}
				}
			}

			require.NotEmpty(t, want)
			require.Equal(t, want, got, person.Name)

		case KindManager:
			// read on every secret of every team in the group
			want := map[SecretRef]Ops{}
			for _, l := range all {
				if l.sec.App.Team.Parent == person.Group.Manager {
					want[l.ref] = Ops{Read: true}
				}
			}

			require.NotEmpty(t, want)
			require.Equal(t, want, got, person.Name)

		case KindDeveloper:
			// rw on settings and keys, read on the read-only database
			// credential, of their team's apps
			want := map[SecretRef]Ops{}
			for _, l := range all {
				if l.sec.App.Team != person.Team {
					continue
				}

				switch l.sec.Thing + "/" + l.sec.Name {
				case "config/settings", "api/key":
					want[l.ref] = Ops{Read: true, Write: true}
				case "db/read":
					want[l.ref] = Ops{Read: true}
				}
			}

			require.Equal(t, want, got, person.Name)

		case KindOps:
			// read on settings, rw on every database credential, of the
			// group's apps
			want := map[SecretRef]Ops{}
			for _, l := range all {
				if l.sec.App.Team.Parent != person.Group.Manager {
					continue
				}

				switch l.sec.Thing {
				case "config":
					want[l.ref] = Ops{Read: true}
				case "db":
					want[l.ref] = Ops{Read: true, Write: true}
				}
			}

			require.Equal(t, want, got, person.Name)

		case KindOpsManager:
			// exactly the union of their ops engineers' access
			want := map[SecretRef]Ops{}
			for _, g := range person.OpsManager.Groups {
				for _, ops := range g.Ops {
					for ref, o := range p.Access(ops) {
						want[ref] = Ops{Read: want[ref].Read || o.Read, Write: want[ref].Write || o.Write}
					}
				}
			}

			require.NotEmpty(t, want)
			require.Equal(t, want, got, person.Name)
		}
	}

	require.Len(t, kinds, 6, "every kind of person is checked")
	require.Greater(t, kinds[KindOpsManager], 1, "more than one ops manager")
}

func TestShowListsTheNewPrincipals(t *testing.T) {
	p := load(t, `
cluster "c" {
  model "m" {
    apps      = 3
    databases = "100%"
    platforms = { kubernetes = "100%" }
  }
}
`)

	var b bytes.Buffer
	require.NoError(t, RenderJSON(&b, p, RenderOptions{}))

	var jp jsonPlan
	require.NoError(t, json.Unmarshal(b.Bytes(), &jp))

	team := p.Apps[0].Team.Name
	var settings []jsonGrant
	for _, m := range jp.Clusters[0].Namespaces[0].Mounts {
		for _, sec := range m.Secrets {
			if sec.App == p.Apps[0].Name && sec.Env == "dev" && sec.Thing == "config" {
				settings = sec.Grants
			}
		}
	}

	require.Equal(t, []jsonGrant{
		{Who: "app", Principal: p.Apps[0].Name, Ops: "r"},
		{Who: "developers", Principal: team + "-developers", Ops: "rw"},
		{Who: "testers", Principal: team + "-testers", Ops: "r"},
		{Who: "managers", Principal: "cto-manager", Ops: "r"},
		{Who: "ops", Principal: "cto-ops", Ops: "r"},
	}, settings)

	b.Reset()
	require.NoError(t, Render(&b, p, RenderOptions{Plain: true}))
	require.Contains(t, b.String(), "settings  app r · developers rw · testers r · managers r · ops r")
}
