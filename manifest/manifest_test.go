package manifest

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nicholasjackson/vault-estate/estate"
)

var customerNames = []string{"startup", "noths", "scaleup", "bank", "retail-group"}

// built caches each example customer's estate and manifest, so the tests
// generate the large customers once.
var built = struct {
	sync.Mutex
	plans     map[string]*estate.Plan
	manifests map[string]*Manifest
}{plans: map[string]*estate.Plan{}, manifests: map[string]*Manifest{}}

// customerConfig loads an example customer's description.
func customerConfig(t *testing.T, name string) estate.Config {
	t.Helper()

	cfgs, err := estate.Load("../examples")
	require.NoError(t, err)

	for _, c := range cfgs {
		if c.Name() == name {
			return c
		}
	}

	require.FailNow(t, "no customer "+name)

	return estate.Config{}
}

// generateCustomer builds and generates an example customer.
func generateCustomer(t *testing.T, name string) (*estate.Plan, *Manifest) {
	t.Helper()

	built.Lock()
	defer built.Unlock()

	if m, ok := built.manifests[name]; ok {
		return built.plans[name], m
	}

	p, err := estate.Build(customerConfig(t, name))
	require.NoError(t, err)

	m, err := Generate(p)
	require.NoError(t, err)

	built.plans[name], built.manifests[name] = p, m

	return p, m
}

// generateText builds and generates the one cluster block in text.
func generateText(t *testing.T, text string) (*estate.Plan, *Manifest) {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cluster.xcl"), []byte(text), 0o600))

	cfgs, err := estate.Load(dir)
	require.NoError(t, err)
	require.Len(t, cfgs, 1)

	p, err := estate.Build(cfgs[0])
	require.NoError(t, err)

	m, err := Generate(p)
	require.NoError(t, err)

	return p, m
}

func encode(t *testing.T, m *Manifest) []byte {
	t.Helper()

	var b bytes.Buffer
	require.NoError(t, Write(&b, m))

	return b.Bytes()
}

func TestEveryCustomerGenerates(t *testing.T) {
	for _, name := range customerNames {
		_, m := generateCustomer(t, name)

		b := encode(t, m)
		require.True(t, json.Valid(b), name)
		require.Equal(t, byte('\n'), b[len(b)-1], "a trailing newline")

		require.Equal(t, name, m.Customer)
		require.NotEmpty(t, m.Clusters, name)
	}
}

func TestManifestMatchesEstate(t *testing.T) {
	for _, name := range customerNames {
		p, m := generateCustomer(t, name)

		// every secret in the manifest, by where it sits
		inManifest := map[estate.SecretRef]Secret{}
		for _, c := range m.Clusters {
			for _, ns := range c.Namespaces {
				for _, sm := range ns.SecretMounts {
					for _, sec := range sm.Secrets {
						ref := estate.SecretRef{Cluster: c.Name, Namespace: ns.Path, Mount: sm.Path, Path: sec.Path}
						_, dup := inManifest[ref]
						require.False(t, dup, "%s: %v twice", name, ref)
						inManifest[ref] = sec
					}
				}
			}
		}

		// every secret in the estate is there, at the same place, with
		// values
		for _, c := range p.Clusters {
			for _, ns := range c.Namespaces {
				for _, mt := range ns.Mounts {
					for _, sec := range mt.Secrets {
						ref := estate.SecretRef{Cluster: c.Name, Namespace: ns.Path, Mount: mt.Path, Path: sec.Path()}
						got, ok := inManifest[ref]
						require.True(t, ok, "%s: %v missing", name, ref)

						require.Equal(t, sec.App.Team.Name+"-"+sec.App.Name, got.App)
						require.Equal(t, sec.Thing, got.Thing)
						require.Equal(t, sec.Name, got.Name)
						require.Equal(t, sec.Env, got.Env)

						require.NotEmpty(t, got.Data, "%s: %v", name, ref)
						for k, v := range got.Data {
							require.NotEmpty(t, k)
							require.NotEmpty(t, v, "%s: %v %s", name, ref, k)
						}

						if sec.Thing == "db" {
							require.NotEmpty(t, got.Data["username"], "%s: %v", name, ref)
							require.NotEmpty(t, got.Data["password"], "%s: %v", name, ref)
						}
					}
				}
			}
		}

		require.Len(t, inManifest, p.Secrets(), name)

		// the same clusters and namespaces, in the same order
		require.Len(t, m.Clusters, len(p.Clusters))
		for i, c := range p.Clusters {
			require.Equal(t, c.Name, m.Clusters[i].Name)
			require.Len(t, m.Clusters[i].Namespaces, len(c.Namespaces))
			for j, ns := range c.Namespaces {
				require.Equal(t, ns.Path, m.Clusters[i].Namespaces[j].Path)
			}
		}

		// and the organisation
		require.Len(t, m.Org.Groups, len(p.Groups))
		require.Len(t, m.Org.OpsManagers, len(p.OpsManagers))
		require.Len(t, m.Org.People, len(p.People))
		for i, g := range m.Org.Groups {
			require.Equal(t, p.Groups[i].Style, g.Style)
			require.Len(t, g.Ops, 2)
			require.Equal(t, g.Name+"-manager", g.Manager)
		}
	}
}

func TestSecretValues(t *testing.T) {
	_, m := generateText(t, `
cluster "c" {
  model "m" {
    apps      = 3
    databases = "100%"
    platforms = { kubernetes = "100%" }
  }
}
`)

	for _, sec := range m.Clusters[0].Namespaces[0].SecretMounts[0].Secrets {
		switch sec.Thing {
		case "db":
			require.Len(t, sec.Data, 2)
			require.Regexp(t, `^[a-z0-9_]+_[a-z]{6}$`, sec.Data["username"])
			require.Regexp(t, `^[A-Za-z0-9]{24}$`, sec.Data["password"])
		case "api":
			require.Regexp(t, `^[a-z_]+_[0-9a-f]{32}$`, sec.Data["api_key"])
		case "config":
			require.GreaterOrEqual(t, len(sec.Data), 2)
			require.LessOrEqual(t, len(sec.Data), 4)
		default:
			require.Fail(t, "unexpected thing "+sec.Thing)
		}
	}
}

func TestManifestDeterministic(t *testing.T) {
	for _, name := range []string{"noths", "scaleup"} {
		gen := func(seed int) []byte {
			cfg := customerConfig(t, name)
			if seed != 0 {
				cfg.Seed = seed
			}

			p, err := estate.Build(cfg)
			require.NoError(t, err)

			m, err := Generate(p)
			require.NoError(t, err)

			return encode(t, m)
		}

		a, b := gen(0), gen(0)
		require.Equal(t, a, b, name)

		seed := customerConfig(t, name).Seed
		if seed == 0 {
			seed = 1
		}

		require.NotEqual(t, a, gen(seed+1), name)
	}
}

func TestRoundTrip(t *testing.T) {
	for _, name := range customerNames {
		_, m := generateCustomer(t, name)

		b := encode(t, m)

		back, err := Read(bytes.NewReader(b))
		require.NoError(t, err)
		require.Equal(t, m, back, name)
		require.Equal(t, b, encode(t, back), name)
	}
}

// placedMount is an auth mount and where it sits.
type placedMount struct {
	Cluster, Namespace string
	AuthMount
}

// authMounts lists every auth mount in the manifest.
func authMounts(m *Manifest) []placedMount {
	var out []placedMount
	for _, c := range m.Clusters {
		for _, ns := range c.Namespaces {
			for _, am := range ns.AuthMounts {
				out = append(out, placedMount{c.Name, ns.Path, am})
			}
		}
	}

	return out
}

// placedRole is a role and the mount it sits on.
type placedRole struct {
	Mount placedMount
	Role
}

// rolesByApp lists the roles each app id logs in with.
func rolesByApp(m *Manifest) map[string][]placedRole {
	out := map[string][]placedRole{}
	for _, pm := range authMounts(m) {
		for _, r := range pm.Roles {
			for _, id := range r.Apps {
				out[id] = append(out[id], placedRole{pm, r})
			}
		}
	}

	return out
}

// userScopes lists, for each person, the clusters and namespaces they have a
// userpass login in.
func userScopes(t *testing.T, m *Manifest) map[string][]scope {
	t.Helper()

	out := map[string][]scope{}
	for _, pm := range authMounts(m) {
		for _, u := range pm.Users {
			require.Equal(t, TypeUserpass, pm.Type)
			require.Equal(t, "userpass", pm.Path)
			require.Equal(t, u.Name, u.Person)
			require.NotEmpty(t, u.Password, "%s in %s/%s", u.Name, pm.Cluster, pm.Namespace)

			at := scope{pm.Cluster, pm.Namespace}
			require.NotContains(t, out[u.Name], at, "%s twice in one place", u.Name)
			out[u.Name] = append(out[u.Name], at)
		}
	}

	return out
}

func TestLoginMethodsMatchPlatforms(t *testing.T) {
	legacySeen := 0

	for _, name := range customerNames {
		p, m := generateCustomer(t, name)
		roles := rolesByApp(m)

		type legacyKey struct{ group, cluster string }
		legacy := map[legacyKey]map[string]bool{}

		for _, a := range p.Apps {
			id := a.Team.Name + "-" + a.Name
			got := roles[id]
			require.Len(t, got, 1, "%s: app %s (%s) has one login", name, id, a.Platform)
			r := got[0]

			switch a.Platform {
			case estate.PlatformKubernetes:
				require.Equal(t, "kubernetes", r.Mount.Type, "%s: %s", name, id)
				require.Equal(t, id, r.Name)
				require.Equal(t, []string{id}, r.Apps)
			case estate.PlatformVM:
				require.Equal(t, "approle", r.Mount.Type, "%s: %s", name, id)
				require.Equal(t, "approle", r.Mount.Path)
				require.Equal(t, id, r.Name)
				require.Equal(t, []string{id}, r.Apps)
			case estate.PlatformLambda:
				require.Equal(t, "aws", r.Mount.Type, "%s: %s", name, id)
				require.Equal(t, id, r.Name)
				require.Equal(t, []string{id}, r.Apps)
			case estate.PlatformLegacy:
				require.Equal(t, "approle", r.Mount.Type, "%s: %s", name, id)
				require.Equal(t, "approle", r.Mount.Path)
				require.Equal(t, a.Group.Name+"-legacy", r.Name, "%s: %s", name, id)

				k := legacyKey{a.Group.Name, r.Mount.Cluster}
				if legacy[k] == nil {
					legacy[k] = map[string]bool{}
				}

				legacy[k][id] = true
			default:
				require.Fail(t, "unexpected platform "+a.Platform)
			}
		}

		// one ops group's legacy apps share exactly one role, listing them
		// all
		for k, ids := range legacy {
			legacySeen++

			var shared []placedRole
			for _, pm := range authMounts(m) {
				if pm.Cluster != k.cluster {
					continue
				}

				for _, r := range pm.Roles {
					if r.Name == k.group+"-legacy" {
						shared = append(shared, placedRole{pm, r})
					}
				}
			}

			require.Len(t, shared, 1, "%s: group %s has one legacy role on %s", name, k.group, k.cluster)
			require.Len(t, shared[0].Apps, len(ids), "%s: %s", name, k.group)
			for _, id := range shared[0].Apps {
				require.True(t, ids[id], "%s: %s lists %s", name, k.group, id)
			}
		}

		// every person has a username and password login
		users := userScopes(t, m)
		for _, person := range p.People {
			require.NotEmpty(t, users[person.Name], "%s: %s (%s) has a login", name, person.Name, person.Kind)
		}

		require.Len(t, users, len(p.People), "%s: only people have logins", name)
	}

	require.Positive(t, legacySeen, "the examples have legacy apps")
}

func TestKubernetesClusters(t *testing.T) {
	p, m := generateText(t, `
cluster "c" {
  model "m" {
    apps                = 24
    namespace           = "none"
    platforms           = { kubernetes = "75%", vm = "25%" }
    kubernetes_clusters = 3
  }
}
`)

	var kube []placedMount
	for _, pm := range authMounts(m) {
		if pm.Type == "kubernetes" {
			kube = append(kube, pm)
		}
	}

	require.Len(t, kube, 3)

	byPath := map[string]placedMount{}
	for _, pm := range kube {
		byPath[pm.Path] = pm

		require.Equal(t, "c", pm.Cluster)
		require.Equal(t, "", pm.Namespace)
		require.NotEmpty(t, pm.Roles, pm.Path)

		require.Len(t, pm.Config, 1)
		require.Equal(t, "config", pm.Config[0].Path)
		require.Equal(t, true, pm.Config[0].Data["disable_local_ca_jwt"])
		require.NotEmpty(t, pm.Config[0].Data["kubernetes_host"])

		ca, ok := pm.Config[0].Data["kubernetes_ca_cert"].(string)
		require.True(t, ok)
		block, _ := pem.Decode([]byte(ca))
		require.NotNil(t, block, "a PEM CA")
		require.Equal(t, "CERTIFICATE", block.Type)
		_, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
	}

	require.ElementsMatch(t, []string{"k8s-m-1", "k8s-m-2", "k8s-m-3"}, []string{kube[0].Path, kube[1].Path, kube[2].Path})

	apps := 0
	for _, a := range p.Apps {
		if a.Platform != estate.PlatformKubernetes {
			continue
		}

		apps++
		id := a.Team.Name + "-" + a.Name

		var on []string
		for _, pm := range kube {
			for _, r := range pm.Roles {
				if r.Name != id {
					continue
				}

				on = append(on, pm.Path)
				require.Equal(t, []any{a.Name}, r.Config["bound_service_account_names"], id)
				require.Equal(t, []any{a.Team.Name}, r.Config["bound_service_account_namespaces"], id)
				require.Equal(t, "vault", r.Config["audience"], id)
			}
		}

		require.Equal(t, []string{a.KubeCluster}, on, "%s is on its own cluster's mount only", id)
	}

	require.Equal(t, 18, apps)
}

func TestAWSAccounts(t *testing.T) {
	text := func(mounts string) string {
		return `
cluster "c" {
  model "m" {
    apps         = 12
    platforms    = { lambda = "100%" }
    aws_accounts = 4
` + mounts + `
  }
}
`
	}

	awsMounts := func(m *Manifest) []placedMount {
		var out []placedMount
		for _, pm := range authMounts(m) {
			if pm.Type == "aws" {
				out = append(out, pm)
			}
		}

		return out
	}

	checkRoles := func(p *estate.Plan, mounts []placedMount, perAccount bool) {
		accounts := p.AWSAccounts["m"]

		apps := 0
		for _, a := range p.Apps {
			apps++
			id := a.Team.Name + "-" + a.Name
			require.Contains(t, accounts, a.AWSAccount, id)

			var found []placedRole
			for _, pm := range mounts {
				for _, r := range pm.Roles {
					if r.Name == id {
						found = append(found, placedRole{pm, r})
					}
				}
			}

			require.Len(t, found, 1, id)
			r := found[0]
			require.Equal(t, "iam", r.Config["auth_type"])
			require.Equal(t, []any{"arn:aws:iam::" + a.AWSAccount + ":role/" + a.Team.Name + "-" + a.Name}, r.Config["bound_iam_principal_arn"])
			require.Equal(t, false, r.Config["resolve_aws_unique_ids"])

			if perAccount {
				require.Equal(t, "aws-m-"+a.AWSAccount, r.Mount.Path, id)
			}
		}

		require.Equal(t, 12, apps)
	}

	t.Run("shared", func(t *testing.T) {
		p, m := generateText(t, text(""))

		accounts := p.AWSAccounts["m"]
		require.Len(t, accounts, 4)
		for _, acct := range accounts {
			require.Regexp(t, `^[0-9]{12}$`, acct)
		}

		mounts := awsMounts(m)
		require.Len(t, mounts, 1)
		require.Equal(t, "aws-m", mounts[0].Path)

		var paths []string
		for _, cw := range mounts[0].Config {
			paths = append(paths, cw.Path)
		}

		want := []string{"config/client"}
		for _, acct := range accounts {
			want = append(want, "config/sts/"+acct)
		}

		require.ElementsMatch(t, want, paths)
		require.Len(t, paths, 5)

		checkRoles(p, mounts, false)
	})

	t.Run("per-account", func(t *testing.T) {
		p, m := generateText(t, text(`    aws_mounts   = "per-account"`))

		accounts := p.AWSAccounts["m"]
		require.Len(t, accounts, 4)

		mounts := awsMounts(m)
		require.Len(t, mounts, 4)

		var paths, want []string
		for _, pm := range mounts {
			paths = append(paths, pm.Path)
			require.Len(t, pm.Config, 1, pm.Path)
			require.Equal(t, "config/client", pm.Config[0].Path)
			require.NotEmpty(t, pm.Roles, pm.Path)
		}

		for _, acct := range accounts {
			want = append(want, "aws-m-"+acct)
		}

		require.ElementsMatch(t, want, paths)

		checkRoles(p, mounts, true)
	})
}

// appNamespace is the namespace an app's secrets sit in on enterprise, as
// its model's namespace placement says.
func appNamespace(p *estate.Plan, a *estate.App) string {
	switch p.Model(a.Model).Namespace {
	case estate.NamespacePerUnit:
		return a.Team.Unit().Name
	case estate.NamespacePerApp:
		return a.Namespace
	case estate.NamespacePerUnitPerApp:
		return a.Team.Unit().Name + "/" + a.Namespace
	default:
		return ""
	}
}

// personTeams are the teams whose apps a person logs in for.
func personTeams(person *estate.Person) []*estate.Node {
	switch person.Kind {
	case estate.KindManager, estate.KindOps:
		return person.Group.Teams
	case estate.KindOpsManager:
		var out []*estate.Node
		for _, g := range person.OpsManager.Groups {
			out = append(out, g.Teams...)
		}

		return out
	default:
		return []*estate.Node{person.Team}
	}
}

// checkEnterprisePlacement checks that every non-legacy app's login sits in
// its app's namespace, every legacy role above all its apps, and each
// person's logins exactly where loginNamespace says for their teams' apps.
func checkEnterprisePlacement(t *testing.T, p *estate.Plan, m *Manifest, loginNamespace func(a *estate.App) string) {
	t.Helper()

	require.Equal(t, "enterprise", m.Edition)
	require.Len(t, m.Clusters, 1)

	roles := rolesByApp(m)
	for _, a := range p.Apps {
		id := a.Team.Name + "-" + a.Name
		require.Len(t, roles[id], 1, id)
		r := roles[id][0]
		ns := appNamespace(p, a)

		if a.Platform == estate.PlatformLegacy {
			require.True(t, r.Mount.Namespace == "" || r.Mount.Namespace == ns || strings.HasPrefix(ns, r.Mount.Namespace+"/"),
				"%s: legacy role in %q is above %q", id, r.Mount.Namespace, ns)

			continue
		}

		require.Equal(t, ns, r.Mount.Namespace, "%s (%s, %s)", id, a.Model, a.Platform)
	}

	users := userScopes(t, m)
	for _, person := range p.People {
		want := map[string]bool{}
		for _, team := range personTeams(person) {
			for _, a := range team.Apps {
				want[loginNamespace(a)] = true
			}
		}

		got := map[string]bool{}
		for _, at := range users[person.Name] {
			require.Equal(t, m.Clusters[0].Name, at.Cluster)
			got[at.Namespace] = true
		}

		require.Equal(t, want, got, "%s (%s)", person.Name, person.Kind)
	}
}

func TestNamespacePlacement(t *testing.T) {
	t.Run("models", func(t *testing.T) {
		p, m := generateText(t, `
cluster "c" {
  edition = "enterprise"

  model "apps" {
    apps      = 20
    namespace = "per-app"
    platforms = { kubernetes = "40%", vm = "40%", lambda = "20%" }
  }

  model "units" {
    apps      = 20
    namespace = "per-unit"
    platforms = { kubernetes = "40%", vm = "40%", lambda = "20%" }
  }

  model "rooted" {
    apps      = 20
    namespace = "per-unit"
    user_auth = "root"
    platforms = { kubernetes = "40%", vm = "40%", lambda = "20%" }
  }
}
`)

		loginNamespace := func(a *estate.App) string {
			if a.Model == "units" {
				return a.Team.Unit().Name
			}

			return ""
		}

		checkEnterprisePlacement(t, p, m, loginNamespace)

		// someone logs in only in a unit, and a developer of a team whose
		// apps are all in the overridden model logs in only at the root
		users := userScopes(t, m)

		unitOnly, rootedDev := 0, 0
		for _, person := range p.People {
			got := users[person.Name]
			if len(got) == 1 && got[0].Namespace != "" {
				unitOnly++
			}

			if person.Kind != estate.KindDeveloper {
				continue
			}

			allRooted := true
			for _, a := range person.Team.Apps {
				allRooted = allRooted && a.Model == "rooted"
			}

			if allRooted {
				rootedDev++
				require.Equal(t, []scope{{"c", ""}}, got, person.Name)
			}
		}

		require.Positive(t, unitOnly, "people log in in their unit's namespace")
		require.Positive(t, rootedDev, "a team wholly in the rooted model")

		// and the overridden model's apps still log in in their unit
		for _, a := range p.Apps {
			if a.Model == "rooted" {
				require.Equal(t, a.Team.Unit().Name, rolesByApp(m)[a.Team.Name+"-"+a.Name][0].Mount.Namespace)
			}
		}
	})

	t.Run("bank", func(t *testing.T) {
		p, m := generateCustomer(t, "bank")

		// per-unit/per-app: people in their unit
		checkEnterprisePlacement(t, p, m, func(a *estate.App) string { return a.Team.Unit().Name })
	})

	t.Run("retail-group", func(t *testing.T) {
		p, m := generateCustomer(t, "retail-group")

		models := map[string]string{
			"root-splatter":  "root",
			"bu-namespaces":  "unit",
			"acquired":       "unit",
			"app-namespaces": "root", // user_auth = "root" overrides the unit
			"ai-services":    "root",
		}

		checkEnterprisePlacement(t, p, m, func(a *estate.App) string {
			if models[a.Model] == "unit" {
				return a.Team.Unit().Name
			}

			return ""
		})
	})
}

func TestPeopleOnCommunityClusters(t *testing.T) {
	p, m := generateCustomer(t, "scaleup")

	require.Equal(t, "community", m.Edition)
	require.Len(t, m.Clusters, 4)
	require.Equal(t, "scaleup", m.Clusters[0].Name)
	for _, c := range m.Clusters[1:] {
		require.True(t, strings.HasPrefix(c.Name, "scaleup-"), c.Name)
	}

	users := userScopes(t, m)

	multi := 0
	for _, person := range p.People {
		got := map[string]bool{}
		for _, at := range users[person.Name] {
			require.Equal(t, "", at.Namespace, "community logins are at the root")
			got[at.Cluster] = true
		}

		if len(got) > 1 {
			multi++
		}

		for ref := range p.Access(person) {
			require.True(t, got[ref.Cluster], "%s (%s) can reach %v but has no login on %s", person.Name, person.Kind, ref, ref.Cluster)
		}

		// a PM has no access, but logs in beside their team's secrets
		if person.Kind == estate.KindPM {
			for _, a := range person.Team.Apps {
				for _, c := range p.Clusters {
					for _, ns := range c.Namespaces {
						for _, mt := range ns.Mounts {
							for _, sec := range mt.Secrets {
								if sec.App == a {
									require.True(t, got[c.Name], "%s on %s", person.Name, c.Name)
								}
							}
						}
					}
				}
			}
		}
	}

	require.Positive(t, multi, "someone logs in on more than one cluster")
}

// acl is a set of policies compiled for evaluation the way Vault evaluates
// them (knowledge gotchas/vault-policy-evaluation.md): an exact pattern
// wins outright; otherwise, of the patterns that match, only the
// highest-priority one applies. Identical patterns across the policies are
// unioned, and deny in the applying pattern overrides everything.
type acl struct {
	exact map[string][]string
	globs []aclRule
}

// aclRule is a pattern with a wildcard, + or a trailing *.
type aclRule struct {
	pattern   string
	re        *regexp.Regexp
	caps      []string
	firstWild int
	glob      bool
	plus      int
}

// templateRe matches a templated segment such as
// {{identity.entity.aliases.auth_kubernetes_1234.metadata.team}}, its mount
// named by its accessor or, as a manifest writes it before apply, by
// ${accessor:<mount>}.
var templateRe = regexp.MustCompile(`\{\{\s*((?:[^{}$]|\$\{[^{}]*\}|\$)+?)\s*\}\}`)

// expandTemplate fills in the path's templated segments from meta by their
// last dotted key; false when one has no value, which leaves the rule out,
// as Vault does.
func expandTemplate(path string, meta map[string]string) (string, bool) {
	ok := true
	out := templateRe.ReplaceAllStringFunc(path, func(s string) string {
		expr := templateRe.FindStringSubmatch(s)[1]
		key := expr[strings.LastIndex(expr, ".")+1:]

		v, found := meta[key]
		if !found || v == "" {
			ok = false
		}

		return v
	})

	return out, ok
}

func newACL(policies []Policy, meta map[string]string) *acl {
	byPattern := map[string][]string{}
	for _, p := range policies {
		for _, r := range p.Rules {
			path, ok := expandTemplate(r.Path, meta)
			if !ok {
				continue
			}

			byPattern[path] = append(byPattern[path], r.Capabilities...)
		}
	}

	a := &acl{exact: map[string][]string{}}
	for pattern, caps := range byPattern {
		first := strings.IndexAny(pattern, "+*")
		if first < 0 {
			a.exact[pattern] = caps
			continue
		}

		glob := strings.HasSuffix(pattern, "*")
		body := strings.TrimSuffix(pattern, "*")

		segs := strings.Split(body, "/")
		res := make([]string, len(segs))
		plus := 0
		for i, s := range segs {
			if s == "+" {
				res[i] = `[^/]+`
				plus++

				continue
			}

			res[i] = regexp.QuoteMeta(s)
		}

		expr := "^" + strings.Join(res, "/")
		if glob {
			expr += ".*"
		}

		a.globs = append(a.globs, aclRule{
			pattern: pattern, re: regexp.MustCompile(expr + "$"), caps: caps,
			firstWild: first, glob: glob, plus: plus,
		})
	}

	return a
}

// outranks reports whether r takes priority over o when both match.
func (r *aclRule) outranks(o *aclRule) bool {
	switch {
	case r.firstWild != o.firstWild:
		return r.firstWild > o.firstWild
	case r.glob != o.glob:
		return !r.glob
	case r.plus != o.plus:
		return r.plus < o.plus
	case len(r.pattern) != len(o.pattern):
		return len(r.pattern) > len(o.pattern)
	default:
		return r.pattern > o.pattern
	}
}

// capabilities are the effective capabilities on the request path, sorted;
// nil when none apply or the applying pattern denies.
func (a *acl) capabilities(path string) []string {
	caps, ok := a.exact[path]
	if !ok {
		var best *aclRule
		for i := range a.globs {
			r := &a.globs[i]
			if r.re.MatchString(path) && (best == nil || r.outranks(best)) {
				best = r
			}
		}

		if best == nil {
			return nil
		}

		caps = best.caps
	}

	if slices.Contains(caps, "deny") {
		return nil
	}

	out := slices.Clone(caps)
	slices.Sort(out)

	return slices.Compact(out)
}

// evalPolicies returns the effective capabilities the policies give on a
// request path relative to their namespace.
func evalPolicies(policies []Policy, path string, meta map[string]string) []string {
	return newACL(policies, meta).capabilities(path)
}

// opsOf maps capabilities on a secret's data path back to the estate's
// access: read is read, and create or update is write.
func opsOf(caps []string) estate.Ops {
	return estate.Ops{
		Read:  slices.Contains(caps, "read"),
		Write: slices.Contains(caps, "create") || slices.Contains(caps, "update"),
	}
}

func TestEvaluator(t *testing.T) {
	pol := func(rules ...Rule) Policy { return Policy{Name: "p", Rules: rules} }
	rule := func(path string, caps ...string) Rule { return Rule{Path: path, Capabilities: caps} }

	tests := []struct {
		name     string
		policies []Policy
		meta     map[string]string
		path     string
		want     []string
	}{
		{"exact", []Policy{pol(rule("secret/data/a", "read"))}, nil, "secret/data/a", []string{"read"}},
		{"exact is not a prefix", []Policy{pol(rule("secret/data/a", "read"))}, nil, "secret/data/ab", nil},
		{"no rule", []Policy{pol(rule("secret/data/a", "read"))}, nil, "other/data/a", nil},
		{"glob prefix", []Policy{pol(rule("secret/data/a*", "read"))}, nil, "secret/data/abc/d", []string{"read"}},
		{"glob matches itself", []Policy{pol(rule("secret/data/a*", "read"))}, nil, "secret/data/a", []string{"read"}},
		{"glob mismatch", []Policy{pol(rule("secret/data/a*", "read"))}, nil, "secret/data/b", nil},
		{"plus one segment", []Policy{pol(rule("secret/+/a", "read"))}, nil, "secret/x/a", []string{"read"}},
		{"plus not two segments", []Policy{pol(rule("secret/+/a", "read"))}, nil, "secret/x/y/a", nil},
		{"plus not zero segments", []Policy{pol(rule("secret/+/a", "read"))}, nil, "secret/a", nil},
		{"plus then glob", []Policy{pol(rule("secret/+/a/*", "read"))}, nil, "secret/x/a/b/c", []string{"read"}},
		{
			"later wildcard wins", []Policy{pol(rule("secret/*", "read"), rule("secret/data/*", "update"))},
			nil, "secret/data/x", []string{"update"},
		},
		{
			"exact beats wildcard", []Policy{pol(rule("secret/data/*", "read"), rule("secret/data/x", "list"))},
			nil, "secret/data/x", []string{"list"},
		},
		{
			"no glob beats glob", []Policy{pol(rule("secret/data/*", "read"), rule("secret/data/+", "update"))},
			nil, "secret/data/x", []string{"update"},
		},
		{
			"fewer plus wins", []Policy{pol(rule("secret/+/+", "read"), rule("secret/+/x", "update"))},
			nil, "secret/a/x", []string{"update"},
		},
		{
			"longer wins", []Policy{pol(rule("secret/+/a*", "read"), rule("secret/+/ab*", "update"))},
			nil, "secret/x/abc", []string{"update"},
		},
		{
			"lexically greater wins", []Policy{pol(rule("secret/+/+/y", "read"), rule("secret/+/x/+", "update"))},
			nil, "secret/a/x/y", []string{"update"},
		},
		{
			"identical patterns union", []Policy{pol(rule("secret/data/a", "read")), pol(rule("secret/data/a", "update", "read"))},
			nil, "secret/data/a", []string{"read", "update"},
		},
		{
			"different patterns don't union", []Policy{pol(rule("secret/data/*", "read")), pol(rule("secret/data/a", "update"))},
			nil, "secret/data/a", []string{"update"},
		},
		{
			"deny overrides", []Policy{pol(rule("secret/data/a", "read")), pol(rule("secret/data/a", "deny"))},
			nil, "secret/data/a", nil,
		},
		{
			"deny on the applying wildcard", []Policy{pol(rule("secret/*", "read"), rule("secret/data/*", "deny"))},
			nil, "secret/data/x", nil,
		},
		{
			"template from an alias", []Policy{pol(rule("secret/data/{{identity.entity.aliases.auth_kubernetes_1234.metadata.service_account_namespace}}/*", "read"))},
			map[string]string{"service_account_namespace": "checkout"}, "secret/data/checkout/x", []string{"read"},
		},
		{
			"template from a mount named for apply", []Policy{pol(rule("secret/data/{{identity.entity.aliases.${accessor:approle}.metadata.team}}/*", "read"))},
			map[string]string{"team": "checkout"}, "secret/data/checkout/x", []string{"read"},
		},
		{
			"template from the entity", []Policy{pol(rule("secret/data/{{identity.entity.metadata.team}}/{{identity.entity.metadata.app}}", "read"))},
			map[string]string{"team": "checkout", "app": "api"}, "secret/data/checkout/api", []string{"read"},
		},
		{
			"template for someone else", []Policy{pol(rule("secret/data/{{identity.entity.metadata.team}}/*", "read"))},
			map[string]string{"team": "checkout"}, "secret/data/search/x", nil,
		},
		{
			"template without a value", []Policy{pol(rule("secret/data/{{identity.entity.metadata.team}}/*", "read"))},
			nil, "secret/data//x", nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, evalPolicies(tt.policies, tt.path, tt.meta))
		})
	}

	require.Equal(t, estate.Ops{Read: true}, opsOf([]string{"read"}))
	require.Equal(t, estate.Ops{Read: true, Write: true}, opsOf([]string{"create", "delete", "read", "update"}))
	require.Equal(t, estate.Ops{Write: true}, opsOf([]string{"update"}))
	require.Equal(t, estate.Ops{}, opsOf([]string{"list"}))
}

// placedSecret is a manifest secret and where it sits.
type placedSecret struct {
	Ref estate.SecretRef
	Secret
}

// view answers what a login may do from the manifest alone.
type view struct {
	m          *Manifest
	namespaces map[scope]*Namespace
	secrets    map[scope][]placedSecret
	// users are each person's userpass logins
	users map[string][]placedUser
	// groups are the internal groups, and entities the entities by scope
	// and name
	groups   []placedGroup
	entities map[scope]map[string]Entity
	cache    map[string]map[estate.SecretRef]estate.Ops
}

// placedGroup is an internal group and where it sits.
type placedGroup struct {
	At scope
	IdentityGroup
}

// placedUser is a userpass user and where it logs in.
type placedUser struct {
	At scope
	User
}

var views = struct {
	sync.Mutex
	by map[*Manifest]*view
}{by: map[*Manifest]*view{}}

func viewOf(m *Manifest) *view {
	views.Lock()
	defer views.Unlock()

	if v := views.by[m]; v != nil {
		return v
	}

	v := &view{
		m: m, namespaces: map[scope]*Namespace{}, secrets: map[scope][]placedSecret{},
		users: map[string][]placedUser{}, cache: map[string]map[estate.SecretRef]estate.Ops{},
		entities: map[scope]map[string]Entity{},
	}

	for i := range m.Clusters {
		c := &m.Clusters[i]
		for j := range c.Namespaces {
			ns := &c.Namespaces[j]
			at := scope{c.Name, ns.Path}
			v.namespaces[at] = ns

			for _, sm := range ns.SecretMounts {
				for _, sec := range sm.Secrets {
					ref := estate.SecretRef{Cluster: c.Name, Namespace: ns.Path, Mount: sm.Path, Path: sec.Path}
					v.secrets[at] = append(v.secrets[at], placedSecret{ref, sec})
				}
			}

			for _, am := range ns.AuthMounts {
				for _, u := range am.Users {
					v.users[u.Person] = append(v.users[u.Person], placedUser{at, u})
				}
			}

			for _, grp := range ns.Groups {
				v.groups = append(v.groups, placedGroup{at, grp})
			}

			v.entities[at] = map[string]Entity{}
			for _, e := range ns.Entities {
				v.entities[at][e.Name] = e
			}
		}
	}

	views.by[m] = v

	return v
}

// reach is the path prefix that reaches namespace ns from a login in
// namespace login, and whether ns is at or below it.
func reach(login, ns string) (string, bool) {
	switch {
	case login == ns:
		return "", true
	case login == "":
		return ns + "/", true
	case strings.HasPrefix(ns, login+"/"):
		return strings.TrimPrefix(ns, login+"/") + "/", true
	default:
		return "", false
	}
}

// policies are the named policies in the scope.
func (v *view) policies(at scope, names []string) []Policy {
	var out []Policy
	if ns := v.namespaces[at]; ns != nil {
		for _, p := range ns.Policies {
			if slices.Contains(names, p.Name) {
				out = append(out, p)
			}
		}
	}

	return out
}

// access is what a token from a login in the scope, carrying the named
// policies, may do with every secret in the manifest.
func (v *view) access(at scope, names []string, meta map[string]string) map[estate.SecretRef]estate.Ops {
	key := fmt.Sprintf("%v|%v|%v", at, names, meta)
	if out, ok := v.cache[key]; ok {
		return out
	}

	a := newACL(v.policies(at, names), meta)

	out := map[estate.SecretRef]estate.Ops{}
	for s, secs := range v.secrets {
		if s.Cluster != at.Cluster {
			continue
		}

		rel, ok := reach(at.Namespace, s.Namespace)
		if !ok {
			continue
		}

		for _, ps := range secs {
			if ops := opsOf(a.capabilities(rel + ps.Ref.Mount + "/data/" + ps.Ref.Path)); ops != (estate.Ops{}) {
				out[ps.Ref] = ops
			}
		}
	}

	v.cache[key] = out

	return out
}

// personAccess is what a person may do with every secret, from all their
// logins: the policies on the logins, and those of the internal groups
// their entities are members of, filled in from the entity's metadata.
func (v *view) personAccess(name string) map[estate.SecretRef]estate.Ops {
	out := map[estate.SecretRef]estate.Ops{}
	for _, u := range v.users[name] {
		for ref, ops := range v.access(u.At, u.Policies, nil) {
			out[ref] = union(out[ref], ops)
		}
	}

	for _, grp := range v.groups {
		for _, member := range grp.Members {
			if member.Entity != name {
				continue
			}

			e, ok := v.entities[scope{grp.At.Cluster, member.Namespace}][name]
			if !ok {
				continue
			}

			for ref, ops := range v.access(grp.At, grp.Policies, e.Metadata) {
				out[ref] = union(out[ref], ops)
			}
		}
	}

	return out
}

// roleAccess is what an app's role may do with every secret.
func (v *view) roleAccess(r placedRole) map[estate.SecretRef]estate.Ops {
	return v.access(scope{r.Mount.Cluster, r.Mount.Namespace}, r.Policies, r.SecretIDMetadata)
}

func union(a, b estate.Ops) estate.Ops {
	return estate.Ops{Read: a.Read || b.Read, Write: a.Write || b.Write}
}

// estateSecret is an estate secret and where it sits.
type estateSecret struct {
	Ref estate.SecretRef
	estate.Secret
}

func estateSecrets(p *estate.Plan) []estateSecret {
	var out []estateSecret
	for _, c := range p.Clusters {
		for _, ns := range c.Namespaces {
			for _, mt := range ns.Mounts {
				for _, sec := range mt.Secrets {
					out = append(out, estateSecret{estate.SecretRef{Cluster: c.Name, Namespace: ns.Path, Mount: mt.Path, Path: sec.Path()}, sec})
				}
			}
		}
	}

	return out
}

// intended is what the estate grants the kind of principal on the secrets
// keep picks.
func intended(secs []estateSecret, who estate.Who, keep func(estateSecret) bool) map[estate.SecretRef]estate.Ops {
	out := map[estate.SecretRef]estate.Ops{}
	for _, sec := range secs {
		if !keep(sec) {
			continue
		}

		for _, g := range sec.Grants() {
			if g.Who == who {
				out[sec.Ref] = union(out[sec.Ref], g.Ops)
			}
		}
	}

	return out
}

// placedPolicy is a policy and where it sits.
type placedPolicy struct {
	At scope
	Policy
}

// policiesByName lists every policy in the manifest by name.
func policiesByName(m *Manifest) map[string][]placedPolicy {
	out := map[string][]placedPolicy{}
	for _, c := range m.Clusters {
		for _, ns := range c.Namespaces {
			for _, p := range ns.Policies {
				out[p.Name] = append(out[p.Name], placedPolicy{scope{c.Name, ns.Path}, p})
			}
		}
	}

	return out
}

// tidyCaps are the capabilities a tidy policy grants each kind of principal
// on each thing/secret.
var tidyCaps = map[estate.Who]map[string][]string{
	estate.WhoApp: {
		"config/settings": {"read"}, "api/key": {"read"}, "db/read-write": {"read"},
	},
	estate.WhoDevelopers: {
		"config/settings": {"create", "read", "update", "delete"},
		"api/key":         {"create", "read", "update", "delete"},
		"db/read":         {"read"},
	},
	estate.WhoTesters: {
		"config/settings": {"read"}, "api/key": {"read"},
	},
	estate.WhoManagers: {
		"config/settings": {"read"}, "api/key": {"read"},
		"db/read": {"read"}, "db/read-write": {"read"}, "db/admin": {"read"},
	},
	estate.WhoOps: {
		"config/settings": {"read"},
		"db/read":         {"create", "read", "update", "delete"},
		"db/read-write":   {"create", "read", "update", "delete"},
		"db/admin":        {"create", "read", "update", "delete"},
	},
}

func TestTidyPolicies(t *testing.T) {
	t.Run("rules", func(t *testing.T) {
		// one cluster, one namespace, no environments: every policy's rules
		// can be spelled out
		p, m := generateText(t, `
cluster "c" {
  model "m" {
    apps      = 8
    namespace = "none"
    env       = "none"
    databases = "100%"
    platforms = { kubernetes = "50%", vm = "50%" }
  }
}
`)

		require.Len(t, m.Clusters, 1)
		ns := m.Clusters[0].Namespaces[0]
		require.Equal(t, "", ns.Path)

		byName := map[string]Policy{}
		for _, pol := range ns.Policies {
			byName[pol.Name] = pol
		}

		// the rules a principal's policy should have over some apps
		want := func(who estate.Who, apps []*estate.App) []Rule {
			var out []Rule
			for _, sec := range estateSecrets(p) {
				if !slices.Contains(apps, sec.App) {
					continue
				}

				if caps, ok := tidyCaps[who][sec.Thing+"/"+sec.Name]; ok {
					out = append(out, Rule{Path: sec.Ref.Mount + "/data/" + sec.Path(), Capabilities: caps})
				}
			}

			return out
		}

		names := []string{}
		roles := rolesByApp(m)
		for _, a := range p.Apps {
			id := a.Team.Name + "-" + a.Name
			pol, ok := byName[id]
			require.True(t, ok, "%s has a policy named after it", id)
			require.Equal(t, "per-app", pol.Style)
			require.Equal(t, a.Group.Name, pol.Group)
			require.ElementsMatch(t, want(estate.WhoApp, []*estate.App{a}), pol.Rules, id)
			require.Len(t, pol.Rules, 3, "%s: config, API key and read-write credential", id)
			require.Equal(t, []string{id}, roles[id][0].Policies, id)
			require.Contains(t, pol.Text, `path "`+pol.Rules[0].Path+`" {`)
			names = append(names, id)
		}

		require.NotEmpty(t, p.Groups)
		for _, g := range p.Groups {
			for _, team := range g.Teams {
				for who, name := range map[estate.Who]string{estate.WhoDevelopers: team.Name + "-developers", estate.WhoTesters: team.Name + "-testers"} {
					pol, ok := byName[name]
					require.True(t, ok, name)
					require.Equal(t, g.Name, pol.Group, name)
					require.Equal(t, "per-app", pol.Style, name)
					require.ElementsMatch(t, want(who, team.Apps), pol.Rules, name)
					names = append(names, name)
				}
			}

			var apps []*estate.App
			for _, team := range g.Teams {
				apps = append(apps, team.Apps...)
			}

			for who, name := range map[estate.Who]string{estate.WhoManagers: g.Name + "-manager", estate.WhoOps: g.Name + "-ops"} {
				pol, ok := byName[name]
				require.True(t, ok, name)
				require.Equal(t, g.Name, pol.Group, name)
				require.ElementsMatch(t, want(who, apps), pol.Rules, name)
				names = append(names, name)
			}
		}

		// and nothing else
		require.Len(t, byName, len(names))
	})

	for _, name := range customerNames {
		t.Run(name, func(t *testing.T) {
			p, m := tidyCustomer(t, name)
			v := viewOf(m)
			secs := estateSecrets(p)
			roles := rolesByApp(m)
			byName := policiesByName(m)

			groups := map[string]bool{}
			for _, g := range p.Groups {
				require.Equal(t, estate.StylePerApp, g.Style, "%s is tidy in the tidy variant", g.Name)
				groups[g.Name] = true
			}

			for _, pols := range byName {
				for _, pol := range pols {
					require.Equal(t, "per-app", pol.Style, pol.Name)
					require.True(t, groups[pol.Group], "%s: group %q", pol.Name, pol.Group)
					require.NotEmpty(t, pol.Rules, pol.Name)
				}
			}

			apps := map[string]*estate.App{}
			for _, a := range p.Apps {
				apps[AppID(a)] = a
			}

			for _, a := range p.Apps {
				id := AppID(a)
				r := roles[id][0]
				at := scope{r.Mount.Cluster, r.Mount.Namespace}

				// the role reaches exactly its apps' secrets, as the estate
				// grants the apps
				var mine []*estate.App
				for _, other := range r.Apps {
					mine = append(mine, apps[other])
				}

				require.Equal(t, intended(secs, estate.WhoApp, func(s estateSecret) bool { return slices.Contains(mine, s.App) }), v.roleAccess(r), "%s: role %s", id, r.Name)

				// each of the app's environments has a policy of its own on
				// the role, granting that environment's secrets only
				envs := map[string]bool{}
				for _, sec := range secs {
					if sec.App == a {
						envs[sec.Env] = true
					}
				}

				require.NotEmpty(t, envs, id)
				for env := range envs {
					pname := id
					if env != "" {
						pname += "-" + env
					}

					require.Contains(t, r.Policies, pname, id)
					require.Equal(t, a.Group.Name, policyAt(t, m, at, pname).Group, pname)
					require.Equal(t,
						intended(secs, estate.WhoApp, func(s estateSecret) bool { return s.App == a && s.Env == env }),
						v.access(at, []string{pname}, nil),
						"%s grants exactly %s's %q secrets", pname, id, env)
				}
			}

			// each team role, manager and ops group has a policy, wherever
			// its people log in, granting together exactly the estate's
			// access
			principal := func(pname string, who estate.Who, keep func(estateSecret) bool) {
				t.Helper()

				copies := byName[pname]
				require.NotEmpty(t, copies, pname)

				got := map[estate.SecretRef]estate.Ops{}
				for _, c := range copies {
					for ref, ops := range v.access(c.At, []string{pname}, nil) {
						got[ref] = union(got[ref], ops)
					}
				}

				require.Equal(t, intended(secs, who, keep), got, pname)
			}

			for _, g := range p.Groups {
				for _, team := range g.Teams {
					mine := func(s estateSecret) bool { return s.App.Team == team }
					principal(team.Name+"-developers", estate.WhoDevelopers, mine)
					principal(team.Name+"-testers", estate.WhoTesters, mine)
				}

				group := func(s estateSecret) bool { return slices.Contains(g.Teams, s.App.Team) }
				principal(g.Name+"-manager", estate.WhoManagers, group)
				principal(g.Name+"-ops", estate.WhoOps, group)
			}
		})
	}
}

// policyAt returns the named policy in the scope.
func policyAt(t *testing.T, m *Manifest, at scope, name string) Policy {
	t.Helper()

	ns := viewOf(m).namespaces[at]
	require.NotNil(t, ns, "%v", at)
	for _, p := range ns.Policies {
		if p.Name == name {
			return p
		}
	}

	require.FailNow(t, fmt.Sprintf("no policy %s in %v", name, at))

	return Policy{}
}

func TestPeoplesGrants(t *testing.T) {
	for _, name := range customerNames {
		t.Run(name, func(t *testing.T) {
			p, m := tidyCustomer(t, name)
			v := viewOf(m)

			// every person may do exactly what the estate intends, from
			// their logins alone
			for _, person := range p.People {
				require.Equal(t, p.Access(person), v.personAccess(person.Name), "%s (%s)", person.Name, person.Kind)
			}

			// and, from the manifest alone: the secrets of each team and
			// group
			var all []placedSecret
			for _, secs := range v.secrets {
				all = append(all, secs...)
			}

			groups := map[string]Group{}
			for _, g := range m.Org.Groups {
				groups[g.Name] = g
			}

			reads := func(keep func(placedSecret) bool) map[estate.SecretRef]estate.Ops {
				out := map[estate.SecretRef]estate.Ops{}
				for _, sec := range all {
					if keep(sec) {
						out[sec.Ref] = estate.Ops{Read: true}
					}
				}

				return out
			}

			seen := map[string]int{}
			for _, person := range m.Org.People {
				got := v.personAccess(person.Name)

				switch person.Kind {
				case estate.KindManager:
					// reads every secret of every team under them, and
					// nothing outside
					teams := groups[person.Group].Teams
					want := reads(func(s placedSecret) bool { return slices.Contains(teams, s.Team) })
					require.NotEmpty(t, want, person.Name)
					require.Equal(t, want, got, person.Name)
					seen[person.Kind]++

				case estate.KindTester:
					// reads their team's configuration and API keys only
					want := reads(func(s placedSecret) bool {
						return s.Team == person.Team && (s.Thing+"/"+s.Name == "config/settings" || s.Thing+"/"+s.Name == "api/key")
					})
					require.NotEmpty(t, want, person.Name)
					require.Equal(t, want, got, person.Name)
					seen[person.Kind]++

				case estate.KindPM:
					// logs in, with no policy granting anything
					require.NotEmpty(t, v.users[person.Name], person.Name)
					for _, u := range v.users[person.Name] {
						require.Empty(t, u.Policies, person.Name)
					}

					require.Empty(t, got, person.Name)
					seen[person.Kind]++

				case estate.KindOpsManager:
					// exactly the union of their ops engineers'
					var om OpsManager
					for _, o := range m.Org.OpsManagers {
						if o.Name == person.Name {
							om = o
						}
					}

					require.NotEmpty(t, om.Groups, person.Name)

					want := map[estate.SecretRef]estate.Ops{}
					for _, g := range om.Groups {
						for _, ops := range groups[g].Ops {
							for ref, o := range v.personAccess(ops) {
								want[ref] = union(want[ref], o)
							}
						}
					}

					require.NotEmpty(t, want, person.Name)
					require.Equal(t, want, got, person.Name)
					seen[person.Kind]++
				}
			}

			for _, kind := range []string{estate.KindManager, estate.KindTester, estate.KindPM, estate.KindOpsManager} {
				require.Positive(t, seen[kind], kind)
			}
		})
	}
}

// customerManifests are the example manifests and a few inline ones.
func customerManifests(t *testing.T) map[string]*Manifest {
	t.Helper()

	out := map[string]*Manifest{}
	for _, name := range customerNames {
		_, out[name] = generateCustomer(t, name)
	}

	_, out["inline"] = generateText(t, `
cluster "c" {
  edition = "enterprise"

  model "apps" {
    apps      = 12
    namespace = "per-app"
    env       = "none"
    databases = "50%"
    platforms = { kubernetes = "40%", vm = "20%", lambda = "20%", legacy = "20%" }
  }

  model "nested" {
    apps      = 12
    namespace = "per-unit/per-app"
    databases = "50%"
    platforms = { kubernetes = "50%", legacy = "50%" }
  }
}
`)

	return out
}

func TestEveryPolicyAttached(t *testing.T) {
	for name, m := range customerManifests(t) {
		checkEveryPolicyAttached(t, name, m)
	}
}

// checkEveryPolicyAttached checks every policy in the manifest is attached
// to a role, a user or an internal group in its own namespace, except the
// legacy style's deliberate orphans, which are attached to nothing; and
// every policy a login or group names is there beside it.
func checkEveryPolicyAttached(t *testing.T, name string, m *Manifest) {
	t.Helper()

	policies := 0
	for _, c := range m.Clusters {
		for _, ns := range c.Namespaces {
			attached := map[string]bool{}
			for _, am := range ns.AuthMounts {
				for _, r := range am.Roles {
					for _, pname := range r.Policies {
						attached[pname] = true
					}
				}

				for _, u := range am.Users {
					for _, pname := range u.Policies {
						attached[pname] = true
					}
				}
			}

			for _, grp := range ns.Groups {
				for _, pname := range grp.Policies {
					attached[pname] = true
				}
			}

			defined := map[string]bool{}
			for _, pol := range ns.Policies {
				policies++
				defined[pol.Name] = true

				if slices.Contains(pol.Quirks, QuirkOrphan) {
					require.False(t, attached[pol.Name], "%s: orphan %s in %s/%q is attached", name, pol.Name, c.Name, ns.Path)
				} else {
					require.True(t, attached[pol.Name], "%s: %s in %s/%q is attached to no login or group", name, pol.Name, c.Name, ns.Path)
				}
			}

			// and every login's policy is there beside it
			for pname := range attached {
				require.True(t, defined[pname], "%s: %s/%q attaches %s, which isn't there", name, c.Name, ns.Path, pname)
			}
		}
	}

	require.Positive(t, policies, name)
}

func TestIdentityOffAttachesDirectly(t *testing.T) {
	ms := customerManifests(t)
	_, ms["off"] = generateText(t, `
cluster "c" {
  identity = false

  model "m" {
    apps      = 10
    namespace = "none"
    platforms = { kubernetes = "50%", vm = "25%", legacy = "25%" }
  }
}
`)

	checked := 0
	for name, m := range ms {
		if m.Identity {
			continue
		}

		kinds := map[string]string{}
		for _, person := range m.Org.People {
			kinds[person.Name] = person.Kind
		}

		roles, users := 0, 0
		for _, c := range m.Clusters {
			for _, ns := range c.Namespaces {
				require.Empty(t, ns.Groups, "%s: %s/%q", name, c.Name, ns.Path)

				// no person has an entity; the only entities are the
				// pre-created aliases of templated Lambda apps
				for _, e := range ns.Entities {
					require.Empty(t, kinds[e.Name], "%s: person %s has an entity", name, e.Name)
					require.Len(t, e.Aliases, 1, e.Name)
					require.True(t, strings.HasPrefix(e.Aliases[0].Mount, "aws-"), "%s: %s", name, e.Name)
					require.NotEmpty(t, e.Aliases[0].CustomMetadata["app"], e.Name)
				}

				for _, am := range ns.AuthMounts {
					for _, r := range am.Roles {
						roles++
						require.NotEmpty(t, r.Policies, "%s: role %s in %s/%q", name, r.Name, c.Name, ns.Path)
					}

					for _, u := range am.Users {
						users++
						if kinds[u.Person] == estate.KindPM {
							require.Empty(t, u.Policies, "%s: %s", name, u.Name)
						} else {
							require.NotEmpty(t, u.Policies, "%s: %s (%s) in %s/%q", name, u.Name, kinds[u.Person], c.Name, ns.Path)
						}
					}
				}
			}
		}

		require.Positive(t, roles, name)
		require.Positive(t, users, name)
		checked++
	}

	require.GreaterOrEqual(t, checked, 3, "startup, scaleup and bank have identity off")
}

func TestPeopleReachChildNamespaces(t *testing.T) {
	p, m := generateText(t, `
cluster "c" {
  edition = "enterprise"

  model "apps" {
    apps      = 12
    namespace = "per-app"
    databases = "50%"
    platforms = { kubernetes = "40%", vm = "20%", legacy = "40%" }
  }

  model "nested" {
    apps      = 12
    namespace = "per-unit/per-app"
    databases = "50%"
    platforms = { kubernetes = "50%", legacy = "50%" }
  }

  model "rooted" {
    apps      = 12
    namespace = "per-unit/per-app"
    user_auth = "root"
    databases = "50%"
    platforms = { kubernetes = "50%", vm = "50%" }
  }
}
`)

	v := viewOf(m)
	byName := policiesByName(m)
	cluster := m.Clusters[0].Name

	// the path a person's policy in the namespace login uses for each
	// secret, as the app's model places it
	loginNS := map[string]func(a *estate.App) string{
		"apps":   func(*estate.App) string { return "" },
		"nested": func(a *estate.App) string { return a.Team.Unit().Name },
		"rooted": func(*estate.App) string { return "" },
	}

	prefixed := map[string]int{}
	for _, sec := range estateSecrets(p) {
		a := sec.App
		login := loginNS[a.Model](a)
		require.Equal(t, appNamespace(p, a), sec.Ref.Namespace)

		var prefix string
		switch a.Model {
		case "apps":
			prefix = a.Namespace + "/" // root reaching its-app
		case "nested":
			prefix = a.Namespace + "/" // unit reaching unit/its-app
		case "rooted":
			prefix = a.Team.Unit().Name + "/" + a.Namespace + "/" // root reaching unit/its-app
		}

		path := prefix + sec.Ref.Mount + "/data/" + sec.Path()

		// the team's developers' policy in the login namespace names the
		// secret by its relative path
		if caps, ok := tidyCaps[estate.WhoDevelopers][sec.Thing+"/"+sec.Name]; ok {
			pol := policyAt(t, m, scope{cluster, login}, a.Team.Name+"-developers")
			require.Contains(t, pol.Rules, Rule{Path: path, Capabilities: caps}, "%s (%s)", sec.Ref, a.Model)
			prefixed[a.Model]++
		}

		// the group manager's too
		pol := policyAt(t, m, scope{cluster, login}, a.Group.Name+"-manager")
		require.Contains(t, pol.Rules, Rule{Path: path, Capabilities: []string{"read"}}, "%s (%s)", sec.Ref, a.Model)
	}

	for model := range loginNS {
		require.Positive(t, prefixed[model], model)
	}

	// no people's policy in the root or a unit names a secret without its
	// namespace
	for pname, pols := range byName {
		if !strings.HasSuffix(pname, "-developers") && !strings.HasSuffix(pname, "-testers") &&
			!strings.HasSuffix(pname, "-manager") && !strings.HasSuffix(pname, "-ops") {
			continue
		}

		for _, pol := range pols {
			for _, r := range pol.Rules {
				require.False(t, strings.HasPrefix(r.Path, "secret/"), "%s in %q: %s", pname, pol.At.Namespace, r.Path)
			}
		}
	}

	// each person reaches exactly their intended secrets from their root
	// or unit logins
	units := 0
	for _, person := range p.People {
		for _, u := range v.users[person.Name] {
			require.True(t, u.At.Namespace == "" || !strings.Contains(u.At.Namespace, "/"), "%s logs in at the root or a unit: %q", u.Name, u.At.Namespace)
			if u.At.Namespace != "" {
				units++
			}
		}

		require.Equal(t, p.Access(person), v.personAccess(person.Name), "%s (%s)", person.Name, person.Kind)
	}

	require.Positive(t, units, "someone logs in in a unit")

	// and each app's role, its legacy AppRole above its namespaces among
	// them, reaches exactly its apps' secrets
	secs := estateSecrets(p)
	legacy := 0
	for _, r := range rolesByApp(m) {
		role := r[0]
		want := intended(secs, estate.WhoApp, func(s estateSecret) bool { return slices.Contains(role.Apps, AppID(s.App)) })
		require.Equal(t, want, v.roleAccess(role), role.Name)

		if !strings.HasSuffix(role.Name, "-legacy") {
			continue
		}

		// a legacy role above its apps' namespaces carries their policies,
		// written in its own namespace with the apps' namespaces prefixed
		at := scope{role.Mount.Cluster, role.Mount.Namespace}
		for _, sec := range secs {
			if !slices.Contains(role.Apps, AppID(sec.App)) || sec.Ref.Namespace == at.Namespace {
				continue
			}

			rel, ok := reach(at.Namespace, sec.Ref.Namespace)
			require.True(t, ok, "%s in %q is above %q", role.Name, at.Namespace, sec.Ref.Namespace)
			require.NotEmpty(t, rel)

			pname := AppID(sec.App)
			if sec.Env != "" {
				pname += "-" + sec.Env
			}

			require.Contains(t, role.Policies, pname, role.Name)
			if caps, ok := tidyCaps[estate.WhoApp][sec.Thing+"/"+sec.Name]; ok {
				require.Contains(t, policyAt(t, m, at, pname).Rules, Rule{Path: rel + sec.Ref.Mount + "/data/" + sec.Path(), Capabilities: caps}, role.Name)
				legacy++
			}
		}
	}

	require.Positive(t, legacy, "a legacy role reaches its apps' namespaces below it")
}

// identityChecks checks a manifest of a customer with identity on: every
// person has an entity, with a userpass alias, wherever they log in; no
// user carries a policy; every group sits with the secrets it grants,
// lists exactly the people its role names and carries its own policy; and
// every person's access through the groups is exactly the estate's.
func identityChecks(t *testing.T, p *estate.Plan, m *Manifest) {
	t.Helper()

	require.True(t, m.Identity)
	v := viewOf(m)

	for _, c := range m.Clusters {
		for _, ns := range c.Namespaces {
			at := scope{c.Name, ns.Path}

			for _, am := range ns.AuthMounts {
				for _, u := range am.Users {
					require.Empty(t, u.Policies, "%v %s: with identity on, policies come through groups", at, u.Name)

					e, ok := v.entities[at][u.Person]
					require.True(t, ok, "%v %s has no entity where they log in", at, u.Person)
					require.Equal(t, []Alias{{Name: u.Name, Mount: "userpass"}}, e.Aliases)
				}
			}

			for _, grp := range ns.Groups {
				require.Equal(t, []string{grp.Name}, grp.Policies, "%v %s", at, grp.Name)
				require.NotEmpty(t, grp.Members)

				// the group's policy is in its own namespace
				policyAt(t, m, at, grp.Name)

				// every member's entity exists, in the group's namespace or above
				for _, mem := range grp.Members {
					_, ok := v.entities[scope{c.Name, mem.Namespace}][mem.Entity]
					require.True(t, ok, "%v %s: member %v has no entity", at, grp.Name, mem)
					_, below := reach(mem.Namespace, ns.Path)
					require.True(t, below, "%v %s: member %v sits below the group", at, grp.Name, mem)
				}
			}
		}
	}

	// each group lists exactly the people the estate puts in it
	members := map[string]map[string]bool{}
	for _, grp := range v.groups {
		if members[grp.Name] == nil {
			members[grp.Name] = map[string]bool{}
		}

		for _, mem := range grp.Members {
			members[grp.Name][mem.Entity] = true
		}
	}

	want := map[string]map[string]bool{}
	add := func(group, person string) {
		if want[group] == nil {
			want[group] = map[string]bool{}
		}

		want[group][person] = true
	}

	for _, person := range p.People {
		switch person.Kind {
		case estate.KindDeveloper:
			add(person.Team.Name+"-developers", person.Name)
		case estate.KindTester:
			add(person.Team.Name+"-testers", person.Name)
		case estate.KindManager:
			add(person.Group.Name+"-manager", person.Name)
		case estate.KindOps:
			add(person.Group.Name+"-ops", person.Name)
		case estate.KindOpsManager:
			for _, g := range person.OpsManager.Groups {
				add(g.Name+"-ops", person.Name)
			}
		}
	}

	require.Equal(t, want, members)

	for _, person := range p.People {
		require.Equal(t, p.Access(person), v.personAccess(person.Name), person.Name)
	}
}

func TestIdentityOn(t *testing.T) {
	p, m := generateText(t, `
cluster "c" {
  identity = true

  model "m" {
    apps      = 30
    databases = "50%"
    platforms = { kubernetes = "40%", vm = "40%", legacy = "20%" }
  }
}
`)

	identityChecks(t, p, m)

	// one cluster, one namespace: everyone's entity and every group is at
	// the root
	require.Len(t, m.Clusters, 1)
	root := m.Clusters[0].Namespaces[0]
	require.Len(t, root.Entities, len(p.People))
	require.NotEmpty(t, root.Groups)

	for _, e := range root.Entities {
		require.NotEmpty(t, e.Metadata["kind"], e.Name)
	}

	// apps keep their policies on their roles
	for _, am := range root.AuthMounts {
		for _, r := range am.Roles {
			require.NotEmpty(t, r.Policies, r.Name)
		}
	}
}

func TestIdentityChildNamespaceGroups(t *testing.T) {
	p, m := generateText(t, `
cluster "c" {
  edition  = "enterprise"
  identity = true

  model "units" {
    apps      = 36
    namespace = "per-unit/per-app"
    databases = "50%"
    platforms = { kubernetes = "50%", vm = "50%" }
  }

  model "apps" {
    apps      = 24
    namespace = "per-app"
    platforms = { kubernetes = "100%" }
  }
}
`)

	identityChecks(t, p, m)

	// people log in at the unit (per-unit/per-app) or the root (per-app);
	// the groups granting them sit in the app namespaces, two or more
	// levels down, with members from the namespace above
	var childGroups, fromAbove int
	for _, c := range m.Clusters {
		for _, ns := range c.Namespaces {
			if len(ns.Groups) > 0 {
				require.NotEmpty(t, ns.SecretMounts, "%s: groups sit with the secrets", ns.Path)
			}

			for _, grp := range ns.Groups {
				if ns.Path != "" {
					childGroups++
				}

				for _, mem := range grp.Members {
					if mem.Namespace != ns.Path {
						fromAbove++
					}
				}

				// a group's policy grants its own namespace's secrets, unprefixed
				for _, r := range policyAt(t, m, scope{c.Name, ns.Path}, grp.Name).Rules {
					require.True(t, strings.HasPrefix(r.Path, "secret/data/"), r.Path)
				}
			}

			for _, e := range ns.Entities {
				require.False(t, strings.Contains(ns.Path, "/"), "%s: entities sit where people log in, not in app namespaces", e.Name)
			}
		}
	}

	require.Positive(t, childGroups)
	require.Positive(t, fromAbove)
}

func TestIdentityOff(t *testing.T) {
	_, m := generateText(t, `
cluster "c" {
  edition = "enterprise"

  model "m" {
    apps      = 24
    namespace = "per-unit/per-app"
    platforms = { kubernetes = "50%", vm = "50%" }
  }
}
`)

	require.False(t, m.Identity)
	for _, c := range m.Clusters {
		for _, ns := range c.Namespaces {
			require.Empty(t, ns.Entities, ns.Path)
			require.Empty(t, ns.Groups, ns.Path)
		}
	}

	for name := range viewOf(m).users {
		require.NotEmpty(t, viewOf(m).users[name], name)
	}
}

func TestTemplatedPolicies(t *testing.T) {
	tests := []struct {
		name string
		text string
		// mixed models leave some groups tidy
		mixed bool
	}{
		{"community identity on", `
cluster "c" {
  identity = true

  model "m" {
    apps      = 40
    databases = "50%"
    platforms = { kubernetes = "30%", vm = "30%", lambda = "20%", legacy = "20%" }
    policies  = { templated = "100%" }
  }
}
`, false},
		{"community identity off", `
cluster "c" {
  model "m" {
    apps         = 40
    namespace    = "per-unit"
    env          = "first"
    databases    = "50%"
    aws_accounts = 2
    aws_mounts   = "per-account"
    platforms    = { kubernetes = "30%", vm = "30%", lambda = "20%", legacy = "20%" }
    policies     = { templated = "100%" }
  }
}
`, false},
		{"enterprise identity on", `
cluster "c" {
  edition  = "enterprise"
  identity = true

  model "units" {
    apps      = 30
    namespace = "per-unit"
    databases = "50%"
    platforms = { kubernetes = "30%", vm = "30%", lambda = "20%", legacy = "20%" }
    policies  = { templated = "100%" }
  }

  model "flat" {
    apps      = 30
    databases = "50%"
    platforms = { kubernetes = "30%", vm = "30%", lambda = "20%", legacy = "20%" }
    policies  = { templated = "100%" }
  }
}
`, false},
		{"enterprise identity on with app namespaces", `
cluster "c" {
  edition  = "enterprise"
  identity = true

  model "apps" {
    apps      = 30
    namespace = "per-unit/per-app"
    databases = "50%"
    platforms = { kubernetes = "30%", vm = "30%", lambda = "20%", legacy = "20%" }
    policies  = { templated = "100%" }
  }
}
`, false},
		{"enterprise identity off", `
cluster "c" {
  edition = "enterprise"

  model "units" {
    apps         = 30
    namespace    = "per-unit"
    env          = "after-app"
    databases    = "50%"
    aws_accounts = 2
    platforms    = { kubernetes = "30%", vm = "30%", lambda = "20%", legacy = "20%" }
    policies     = { templated = "100%" }
  }

  model "apps" {
    apps      = 30
    namespace = "per-unit/per-app"
    user_auth = "root"
    databases = "50%"
    platforms = { kubernetes = "30%", vm = "30%", lambda = "20%", legacy = "20%" }
    policies  = { templated = "100%" }
  }
}
`, false},
		{"mixed styles", `
cluster "c" {
  edition  = "enterprise"
  identity = true

  model "m" {
    apps      = 80
    namespace = "per-unit"
    databases = "50%"
    platforms = { kubernetes = "30%", vm = "30%", lambda = "20%", legacy = "20%" }
    policies  = { per-app = "50%", templated = "50%" }
  }
}
`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, m := generateText(t, tt.text)
			v := viewOf(m)
			secs := estateSecrets(p)
			roles := rolesByApp(m)
			byName := policiesByName(m)

			// a secret's path in its mount with the segments of the given
			// kinds replaced, as a policy rule names it
			templ := func(sec estateSecret, replace map[string]string) string {
				var parts []string
				for _, seg := range sec.Segments() {
					if r, ok := replace[seg.Kind]; ok {
						parts = append(parts, r)
					} else {
						parts = append(parts, seg.Name)
					}
				}

				return sec.Ref.Mount + "/data/" + strings.Join(append(parts, sec.Name), "/")
			}

			alias := func(mount, key string) string {
				return "{{identity.entity.aliases.${accessor:" + mount + "}." + key + "}}"
			}

			anySegment := map[string]string{"team": "+", "app": "+", "env": "+"}
			byTeam := map[string]string{"team": "{{identity.entity.metadata.team}}", "app": "+", "env": "+"}
			identityConfig := ConfigWrite{Path: "config/identity", Data: map[string]any{"iam_alias": "full_arn"}}

			// the rule granting the kind of principal the secret, in a
			// policy at scope at (reaching down to the secret)
			rule := func(at scope, sec estateSecret, who estate.Who, replace map[string]string) (Rule, bool) {
				caps, ok := tidyCaps[who][sec.Thing+"/"+sec.Name]
				if !ok {
					return Rule{}, false
				}

				rel, below := reach(at.Namespace, sec.Ref.Namespace)
				require.True(t, below, "%v reaches %s", at, sec.Ref)

				return Rule{Path: rel + templ(sec, replace), Capabilities: caps}, true
			}

			templated := map[*estate.OpsGroup]bool{}
			for _, g := range p.Groups {
				templated[g] = g.Style == estate.StyleTemplated
			}

			platforms := map[string]int{}
			tidyGroups, templatedRules := 0, 0

			for _, g := range p.Groups {
				if !templated[g] {
					tidyGroups++

					// a tidy group keeps its per-app policies, and its
					// AppRole roles no SecretID metadata
					for _, copies := range byName {
						for _, c := range copies {
							if c.Group == g.Name {
								require.Equal(t, estate.StylePerApp, c.Style, c.Name)
							}
						}
					}

					for _, team := range g.Teams {
						for _, a := range team.Apps {
							require.Nil(t, roles[AppID(a)][0].SecretIDMetadata, AppID(a))
						}
					}

					continue
				}

				var apps []*estate.App
				for _, team := range g.Teams {
					apps = append(apps, team.Apps...)
				}

				// the policy names the group should have, and the scopes
				// of each shared mount policy
				wantNames := map[string]bool{g.Name + "-ops": true, g.Name + "-manager": true}
				if p.Identity {
					wantNames[g.Name+"-developers-templated"] = true
					wantNames[g.Name+"-testers-templated"] = true
				} else {
					for _, team := range g.Teams {
						wantNames[team.Name+"-developers"] = true
						wantNames[team.Name+"-testers"] = true
					}
				}

				mountScopes := map[string]map[scope]bool{}

				for _, a := range apps {
					id := AppID(a)
					require.Len(t, roles[id], 1, id)
					r := roles[id][0]
					at := scope{r.Mount.Cluster, r.Mount.Namespace}
					platforms[a.Platform]++

					mine := intended(secs, estate.WhoApp, func(s estateSecret) bool { return s.App == a })
					require.NotEmpty(t, mine, id)

					envs := map[string]bool{}
					for _, sec := range secs {
						if sec.App == a {
							envs[sec.Env] = true
						}
					}

					if a.Platform == estate.PlatformLegacy {
						// the shared legacy AppRole keeps tidy app-env
						// policies, reaching exactly its apps' secrets
						require.Equal(t, LegacyRole(g.Name), r.Name)
						require.Nil(t, r.SecretIDMetadata, r.Name)
						require.Equal(t, intended(secs, estate.WhoApp, func(s estateSecret) bool { return slices.Contains(r.Apps, AppID(s.App)) }), v.roleAccess(r), r.Name)

						for env := range envs {
							pname := id
							if env != "" {
								pname += "-" + env
							}

							require.Contains(t, r.Policies, pname, r.Name)
							pol := policyAt(t, m, at, pname)
							require.Equal(t, estate.StyleTemplated, pol.Style, pname)
							require.Equal(t, g.Name, pol.Group, pname)
							require.Equal(t,
								intended(secs, estate.WhoApp, func(s estateSecret) bool { return s.App == a && s.Env == env }),
								v.access(at, []string{pname}, nil), pname)
							wantNames[pname] = true
						}

						continue
					}

					// one shared policy for the group on the app's mount, and
					// no policy of the app's own
					pname := g.Name + "-" + r.Mount.Path
					require.Equal(t, []string{pname}, r.Policies, id)
					wantNames[pname] = true
					if mountScopes[pname] == nil {
						mountScopes[pname] = map[scope]bool{}
					}

					mountScopes[pname][at] = true

					require.Empty(t, byName[id], id)
					for env := range envs {
						require.Empty(t, byName[id+"-"+env], id)
					}

					pol := policyAt(t, m, at, pname)
					require.Equal(t, estate.StyleTemplated, pol.Style, pname)
					require.Equal(t, g.Name, pol.Group, pname)

					// the metadata the login fills the policy in from
					var team, app string
					var meta map[string]string
					switch r.Mount.Type {
					case TypeKubernetes:
						team, app = alias(r.Mount.Path, "metadata.service_account_namespace"), alias(r.Mount.Path, "metadata.service_account_name")
						require.Equal(t, []any{a.Team.Name}, r.Config["bound_service_account_namespaces"], id)
						require.Equal(t, []any{a.Name}, r.Config["bound_service_account_names"], id)
						require.Nil(t, r.SecretIDMetadata, id)
						meta = map[string]string{"service_account_namespace": a.Team.Name, "service_account_name": a.Name}

					case TypeAppRole:
						require.Equal(t, estate.PlatformVM, a.Platform, id)
						team, app = alias(r.Mount.Path, "metadata.team"), alias(r.Mount.Path, "metadata.app")
						require.Equal(t, map[string]string{"team": a.Team.Name, "app": a.Name}, r.SecretIDMetadata, id)
						meta = r.SecretIDMetadata

					case TypeAWS:
						team, app = alias(r.Mount.Path, "custom_metadata.team"), alias(r.Mount.Path, "custom_metadata.app")
						require.Nil(t, r.SecretIDMetadata, id)

						// a pre-created alias, named by the role's ARN, with
						// the app's team and name
						arn := "arn:aws:iam::" + a.AWSAccount + ":role/" + id
						require.Equal(t, []any{arn}, r.Config["bound_iam_principal_arn"], id)
						e, ok := v.entities[at][id]
						require.True(t, ok, "%s has an entity in %v", id, at)
						require.Equal(t, Entity{Name: id, Aliases: []Alias{{
							Name: arn, Mount: r.Mount.Path,
							CustomMetadata: map[string]string{"team": a.Team.Name, "app": a.Name},
						}}}, e)
						require.Contains(t, r.Mount.Config, identityConfig, r.Mount.Path)
						meta = map[string]string{"team": a.Team.Name, "app": a.Name}

					default:
						require.FailNow(t, "unexpected mount type "+r.Mount.Type)
					}

					// filled in for the app, the policy grants exactly the
					// app's secrets; not filled in, nothing, unless the
					// app's namespace is its own and its paths name neither
					// team nor app
					require.Equal(t, mine, v.access(at, r.Policies, meta), "%s filled in for %s", pname, id)
					if !slices.ContainsFunc(pol.Rules, func(r Rule) bool { return !strings.Contains(r.Path, "{{") }) {
						require.Empty(t, v.access(at, r.Policies, nil), "%s without metadata", pname)
						templatedRules++
					}
					if r.Mount.Type == TypeAppRole {
						require.Equal(t, mine, v.roleAccess(r), id)
					}

					// its rules template the app's secrets' paths
					for _, sec := range secs {
						if sec.App != a {
							continue
						}

						if want, ok := rule(at, sec, estate.WhoApp, map[string]string{"team": team, "app": app, "env": "+"}); ok {
							require.Contains(t, pol.Rules, want, pname)
						}
					}
				}

				// one copy of each mount policy per place the group's apps
				// log in through the mount
				for pname, scopes := range mountScopes {
					require.Len(t, byName[pname], len(scopes), pname)
				}

				// the group has exactly these policies, all templated
				got := map[string]bool{}
				for name, copies := range byName {
					for _, c := range copies {
						if c.Group == g.Name {
							require.Equal(t, estate.StyleTemplated, c.Style, "%s in %v", name, c.At)
							got[name] = true
						}
					}
				}

				require.Equal(t, wantNames, got, g.Name)

				// the people's rules: ops wildcard in both modes; with
				// identity, the team roles filled in from the entity
				groupSecs := func(who estate.Who, pname string, replace map[string]string) {
					t.Helper()

					n := 0
					for _, sec := range secs {
						if sec.App.Group != g {
							continue
						}

						found := false
						for _, c := range byName[pname] {
							if c.At.Cluster != sec.Ref.Cluster {
								continue
							}

							if _, below := reach(c.At.Namespace, sec.Ref.Namespace); !below {
								continue
							}

							if want, ok := rule(c.At, sec, who, replace); ok {
								n++
								if slices.ContainsFunc(c.Rules, func(r Rule) bool { return r.Path == want.Path && slices.Equal(r.Capabilities, want.Capabilities) }) {
									found = true
								}
							} else {
								found = true
							}
						}

						require.True(t, found, "%s covers %s", pname, sec.Ref)
					}

					require.Positive(t, n, pname)
				}

				groupSecs(estate.WhoOps, g.Name+"-ops", anySegment)
				if p.Identity {
					groupSecs(estate.WhoDevelopers, g.Name+"-developers-templated", byTeam)
					groupSecs(estate.WhoTesters, g.Name+"-testers-templated", byTeam)
					groupSecs(estate.WhoManagers, g.Name+"-manager", anySegment)
				} else {
					for _, team := range g.Teams {
						for _, pname := range []string{team.Name + "-developers", team.Name + "-testers"} {
							for _, c := range byName[pname] {
								require.NotContains(t, c.Text, "{{", pname)
								require.NotContains(t, c.Text, "/+/", pname)
							}
						}
					}
				}
			}

			if tt.mixed {
				require.Positive(t, tidyGroups, "some groups are tidy")
			} else {
				require.Zero(t, tidyGroups, "every group is templated")
			}

			for _, platform := range []string{estate.PlatformKubernetes, estate.PlatformVM, estate.PlatformLambda, estate.PlatformLegacy} {
				require.Positive(t, platforms[platform], "templated %s apps", platform)
			}

			// an AWS mount has config/identity exactly when templated Lambda
			// apps log in through it
			awsMounts := 0
			for _, pm := range authMounts(m) {
				if pm.Type != TypeAWS {
					continue
				}

				awsMounts++
				want := false
				for _, r := range pm.Roles {
					for _, a := range p.Apps {
						if AppID(a) == r.Apps[0] && templated[a.Group] {
							want = true
						}
					}
				}

				has := slices.ContainsFunc(pm.Config, func(c ConfigWrite) bool { return c.Path == identityConfig.Path })
				require.Equal(t, want, has, pm.Path)
				if has {
					require.Contains(t, pm.Config, identityConfig, pm.Path)
				}
			}

			require.Positive(t, awsMounts)

			// where secret paths name their team or app, app policies are
			// filled in
			named := slices.ContainsFunc(secs, func(sec estateSecret) bool {
				return templated[sec.App.Group] && sec.App.Platform != estate.PlatformLegacy &&
					slices.ContainsFunc(sec.Segments(), func(seg estate.Segment) bool { return seg.Kind == "team" || seg.Kind == "app" })
			})
			require.Equal(t, named, templatedRules > 0, "some app policies are filled in")

			// every person reaches exactly what the estate intends: ops,
			// developers, testers and managers, through groups or logins
			for _, person := range p.People {
				require.Equal(t, p.Access(person), v.personAccess(person.Name), "%s (%s)", person.Name, person.Kind)
			}

			if !p.Identity {
				// no internal groups, and the only entities are the Lambda
				// apps' with their pre-created aliases
				for _, c := range m.Clusters {
					for _, ns := range c.Namespaces {
						require.Empty(t, ns.Groups, ns.Path)
						for _, e := range ns.Entities {
							require.Len(t, e.Aliases, 1, e.Name)
							require.True(t, strings.HasPrefix(e.Aliases[0].Mount, "aws-"), e.Name)
						}
					}
				}

				// people get the tidy policies on their logins, and ops
				// the wildcard one
				for _, person := range p.People {
					var want []string
					switch person.Kind {
					case estate.KindDeveloper:
						want = []string{person.Team.Name + "-developers"}
					case estate.KindTester:
						want = []string{person.Team.Name + "-testers"}
					case estate.KindManager:
						want = []string{person.Group.Name + "-manager"}
					case estate.KindOps:
						want = []string{person.Group.Name + "-ops"}
					default:
						continue
					}

					require.NotEmpty(t, v.users[person.Name], person.Name)
					for _, u := range v.users[person.Name] {
						require.Equal(t, want, u.Policies, "%s in %v", person.Name, u.At)
					}
				}

				return
			}

			// identity on: users carry no policies, team-role people's
			// entities carry their team, and the groups carry the policies
			for _, person := range p.People {
				for _, u := range v.users[person.Name] {
					require.Empty(t, u.Policies, "%s in %v", person.Name, u.At)

					e, ok := v.entities[u.At][person.Name]
					require.True(t, ok, "%s has an entity in %v", person.Name, u.At)
					if person.Kind == estate.KindDeveloper || person.Kind == estate.KindTester {
						require.Equal(t, person.Team.Name, e.Metadata["team"], person.Name)
					}
				}
			}

			wantMembers := map[string]map[string]bool{}
			wantPolicies := map[string][]string{}
			add := func(group, policy, person string) {
				if wantMembers[group] == nil {
					wantMembers[group] = map[string]bool{}
				}

				wantMembers[group][person] = true
				wantPolicies[group] = []string{policy}
			}

			for _, person := range p.People {
				switch person.Kind {
				case estate.KindDeveloper:
					if templated[person.Group] {
						add(person.Group.Name+"-developers", person.Group.Name+"-developers-templated", person.Name)
					} else {
						add(person.Team.Name+"-developers", person.Team.Name+"-developers", person.Name)
					}
				case estate.KindTester:
					if templated[person.Group] {
						add(person.Group.Name+"-testers", person.Group.Name+"-testers-templated", person.Name)
					} else {
						add(person.Team.Name+"-testers", person.Team.Name+"-testers", person.Name)
					}
				case estate.KindManager:
					add(person.Group.Name+"-manager", person.Group.Name+"-manager", person.Name)
				case estate.KindOps:
					add(person.Group.Name+"-ops", person.Group.Name+"-ops", person.Name)
				case estate.KindOpsManager:
					for _, g := range person.OpsManager.Groups {
						add(g.Name+"-ops", g.Name+"-ops", person.Name)
					}
				}
			}

			gotMembers := map[string]map[string]bool{}
			for _, grp := range v.groups {
				require.Equal(t, wantPolicies[grp.Name], grp.Policies, "%v %s", grp.At, grp.Name)
				policyAt(t, m, grp.At, grp.Policies[0])

				if gotMembers[grp.Name] == nil {
					gotMembers[grp.Name] = map[string]bool{}
				}

				for _, mem := range grp.Members {
					gotMembers[grp.Name][mem.Entity] = true
				}
			}

			require.Equal(t, wantMembers, gotMembers)
		})
	}
}

// TestTemplatedOpsWildcardStaysInGroup checks that an ops group's wildcard
// policies, <group>-ops and, with identity, <group>-manager, each evaluated
// on their own, reach exactly the group's secrets the estate intends: the +
// segments never stretch to another group's secrets, even on a KV mount
// several groups share.
func TestTemplatedOpsWildcardStaysInGroup(t *testing.T) {
	// the customers where groups with wildcard rules share a KV mount; bank's
	// groups don't, as its namespaces sit per unit
	sharing := map[string]bool{}

	for _, name := range []string{"bank", "retail-group", "scaleup", "noths"} {
		for _, identity := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s identity %v", name, identity), func(t *testing.T) {
				cfg := customerConfig(t, name)
				cfg.Identity = identity
				for i := range cfg.Models {
					cfg.Models[i].Policies = map[string]string{estate.StyleTemplated: "100%"}
				}

				p, err := estate.Build(cfg)
				require.NoError(t, err)

				m, err := Generate(p)
				require.NoError(t, err)

				v := viewOf(m)
				byName := policiesByName(m)

				// the ops groups with secrets on each KV mount, and whether
				// each group's secret paths name a team
				type mountAt struct{ cluster, namespace, mount string }
				mountGroups := map[mountAt]map[*estate.OpsGroup]bool{}
				teamPaths := map[*estate.OpsGroup]bool{}
				for _, sec := range estateSecrets(p) {
					k := mountAt{sec.Ref.Cluster, sec.Ref.Namespace, sec.Ref.Mount}
					if mountGroups[k] == nil {
						mountGroups[k] = map[*estate.OpsGroup]bool{}
					}

					mountGroups[k][sec.App.Group] = true
					if slices.ContainsFunc(sec.Segments(), func(seg estate.Segment) bool { return seg.Kind == "team" }) {
						teamPaths[sec.App.Group] = true
					}
				}

				shared := map[*estate.OpsGroup]bool{}
				for _, groups := range mountGroups {
					if len(groups) > 1 {
						for g := range groups {
							shared[g] = true
						}
					}
				}

				// what the policy's copies, each alone in its own scope,
				// reach of every secret in the manifest
				reached := func(pname string) map[estate.SecretRef]estate.Ops {
					t.Helper()

					require.NotEmpty(t, byName[pname], pname)

					out := map[estate.SecretRef]estate.Ops{}
					for _, c := range byName[pname] {
						for ref, ops := range v.access(c.At, []string{pname}, nil) {
							out[ref] = union(out[ref], ops)
						}
					}

					return out
				}

				wildcard := func(pname string) bool {
					for _, c := range byName[pname] {
						for _, r := range c.Rules {
							if strings.Contains("/"+r.Path+"/", "/+/") {
								return true
							}
						}
					}

					return false
				}

				wildShared := 0
				for _, g := range p.Groups {
					require.Equal(t, estate.StyleTemplated, g.Style, g.Name)
					require.Len(t, g.Ops, 2, g.Name)

					policies := map[string]map[estate.SecretRef]estate.Ops{
						g.Name + "-ops": union2(p.Access(g.Ops[0]), p.Access(g.Ops[1])),
					}
					if identity {
						policies[g.Name+"-manager"] = p.Access(g.ManagerPerson)
					}

					for pname, want := range policies {
						require.NotEmpty(t, want, pname)
						require.Equal(t, want, reached(pname), "%s reaches exactly its group's secrets", pname)

						if teamPaths[g] {
							require.True(t, wildcard(pname), "%s has + rules", pname)
						}
					}

					if teamPaths[g] && shared[g] {
						wildShared++
					}
				}

				if wildShared > 0 {
					sharing[name] = true
				}
			})
		}
	}

	// KV mounts several groups share, holding paths a wildcard covers, so
	// the wildcards' containment is exercised
	require.Equal(t, map[string]bool{"retail-group": true, "scaleup": true, "noths": true}, sharing)
}

// union2 merges two access maps.
func union2(a, b map[estate.SecretRef]estate.Ops) map[estate.SecretRef]estate.Ops {
	out := map[estate.SecretRef]estate.Ops{}
	for _, m := range []map[estate.SecretRef]estate.Ops{a, b} {
		for ref, ops := range m {
			out[ref] = union(out[ref], ops)
		}
	}

	return out
}

func TestLegacyPolicies(t *testing.T) {
	cases := map[string]string{
		"community identity off": `
cluster "c" {
  model "m" {
    apps      = 36
    databases = "50%"
    platforms = { kubernetes = "40%", vm = "30%", legacy = "30%" }
    policies  = { legacy = "100%" }
  }
}
`,
		"community identity on, env first": `
cluster "c" {
  identity = true

  model "m" {
    apps      = 36
    env       = "first"
    databases = "50%"
    platforms = { kubernetes = "40%", vm = "30%", legacy = "30%" }
    policies  = { legacy = "100%" }
  }
}
`,
		"enterprise app namespaces, no environments": `
cluster "c" {
  edition = "enterprise"

  model "m" {
    apps      = 36
    namespace = "per-unit/per-app"
    env       = "none"
    databases = "50%"
    platforms = { kubernetes = "40%", vm = "30%", legacy = "30%" }
    policies  = { legacy = "100%" }
  }
}
`,
		"no legacy apps, mixed with tidy": `
cluster "c" {
  identity = true

  model "m" {
    apps      = 48
    databases = "100%"
    platforms = { kubernetes = "50%", vm = "50%" }
    policies  = { legacy = "50%", per-app = "50%" }
  }
}
`,
	}

	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			p, m := generateText(t, text)
			v := viewOf(m)

			// every secret's data path, for checking dead rules
			type located struct {
				at   scope
				path string
			}

			var secrets []located
			for at, secs := range v.secrets {
				for _, ps := range secs {
					secrets = append(secrets, located{at, ps.Ref.Mount + "/data/" + ps.Ref.Path})
				}
			}

			attached := map[string]bool{}
			for _, c := range m.Clusters {
				for _, ns := range c.Namespaces {
					for _, am := range ns.AuthMounts {
						for _, r := range am.Roles {
							for _, pname := range r.Policies {
								attached[pname] = true
							}
						}

						for _, u := range am.Users {
							for _, pname := range u.Policies {
								attached[pname] = true
							}
						}
					}

					for _, grp := range ns.Groups {
						for _, pname := range grp.Policies {
							attached[pname] = true
						}
					}
				}
			}

			legacyGroups := 0
			for _, group := range p.Groups {
				if group.Style != estate.StyleLegacy {
					continue
				}

				legacyGroups++

				// the group's policies, all in the legacy style, with their quirks
				quirks := map[string][]Policy{}
				var all []Policy
				for _, c := range m.Clusters {
					for _, ns := range c.Namespaces {
						for _, pol := range ns.Policies {
							if pol.Group != group.Name {
								continue
							}

							require.Equal(t, estate.StyleLegacy, pol.Style, pol.Name)
							all = append(all, pol)
							for _, q := range pol.Quirks {
								quirks[q] = append(quirks[q], pol)
							}
						}
					}
				}

				// the shared AppRole with a group-wide wildcard, even without
				// legacy apps
				found := false
				for _, pm := range authMounts(m) {
					for _, r := range pm.Roles {
						if r.Name == group.Name+"-legacy" {
							found = true
							require.Equal(t, []string{group.Name + "-legacy"}, r.Policies)
						}
					}
				}

				require.True(t, found, "%s has no shared AppRole", group.Name)

				var wildcard bool
				for _, pol := range quirks[QuirkWildcard] {
					if pol.Name == group.Name+"-legacy" {
						for _, r := range pol.Rules {
							if strings.HasSuffix(r.Path, "*") && strings.Contains(r.Path, "/data/") {
								wildcard = true
							}
						}
					}
				}

				require.True(t, wildcard, "%s: shared AppRole has no group-wide wildcard", group.Name)

				// environment-wide policies on people, one with a deny
				require.NotEmpty(t, quirks[QuirkEnvWide], group.Name)
				for _, pol := range quirks[QuirkEnvWide] {
					require.True(t, attached[pol.Name], pol.Name)
				}

				var deny bool
				for _, pol := range quirks[QuirkDeny] {
					for _, r := range pol.Rules {
						if slices.Contains(r.Capabilities, "deny") {
							deny = true
							require.True(t, strings.HasSuffix(r.Path, "/db/admin"), r.Path)
						}
					}
				}

				require.True(t, deny, "%s has no deny rule", group.Name)

				// a broad ops grant with sudo, and a near-duplicate pair
				var sudo bool
				for _, pol := range quirks[QuirkSudo] {
					for _, r := range pol.Rules {
						sudo = sudo || slices.Contains(r.Capabilities, "sudo")
					}
				}

				require.True(t, sudo, group.Name)
				require.GreaterOrEqual(t, len(quirks[QuirkNearDuplicate]), 2, group.Name)

				// rules matching no secret
				require.NotEmpty(t, quirks[QuirkDeadRule], group.Name)
				for _, pol := range quirks[QuirkDeadRule] {
					for _, r := range pol.Rules {
						if strings.Contains(r.Path, "/data/") {
							continue
						}

						for _, sec := range secrets {
							rel, ok := reach("", sec.at.Namespace)
							require.True(t, ok)
							require.Empty(t, evalPolicies([]Policy{{Rules: []Rule{r}}}, rel+sec.path, nil), "dead rule %s matches %s", r.Path, sec.path)
							require.Empty(t, evalPolicies([]Policy{{Rules: []Rule{r}}}, sec.path, nil), "dead rule %s matches %s", r.Path, sec.path)
						}
					}
				}

				// an orphan attached to nothing
				require.NotEmpty(t, quirks[QuirkOrphan], group.Name)
				for _, pol := range quirks[QuirkOrphan] {
					require.False(t, attached[pol.Name], pol.Name)
					require.True(t, strings.HasSuffix(pol.Name, "-old"), pol.Name)
				}

				require.NotEmpty(t, all)
			}

			require.Positive(t, legacyGroups)

			// every policy is attached, except the orphans
			checkEveryPolicyAttached(t, name, m)
		})
	}
}

func TestLegacyEveryoneLogsIn(t *testing.T) {
	p, m := generateText(t, `
cluster "c" {
  edition  = "enterprise"
  identity = true

  model "m" {
    apps      = 36
    namespace = "per-unit/per-app"
    platforms = { kubernetes = "40%", vm = "30%", legacy = "30%" }
    policies  = { legacy = "100%" }
  }
}
`)

	roles := rolesByApp(m)
	for _, a := range p.Apps {
		require.Len(t, roles[AppID(a)], 1, AppID(a))
		require.NotEmpty(t, roles[AppID(a)][0].Policies, AppID(a))
	}

	users := userScopes(t, m)
	for _, person := range p.People {
		require.NotEmpty(t, users[person.Name], person.Name)
	}

	// everyone who should reach a secret still does, through the mess
	v := viewOf(m)
	for _, person := range p.People {
		got := v.personAccess(person.Name)
		for ref, ops := range p.Access(person) {
			require.True(t, got[ref].Read || !ops.Read, "%s lost read on %v", person.Name, ref)
		}
	}
}

// tidyCustomer builds and generates an example customer with every model
// on the tidy style and identity off: the real shapes, all tidy.
func tidyCustomer(t *testing.T, name string) (*estate.Plan, *Manifest) {
	t.Helper()

	key := name + " (tidy)"

	built.Lock()
	defer built.Unlock()

	if m, ok := built.manifests[key]; ok {
		return built.plans[key], m
	}

	cfg := customerConfig(t, name)
	cfg.Identity = false
	for i := range cfg.Models {
		cfg.Models[i].Policies = nil
	}

	p, err := estate.Build(cfg)
	require.NoError(t, err)

	m, err := Generate(p)
	require.NoError(t, err)

	built.plans[key], built.manifests[key] = p, m

	return p, m
}

func TestExampleCustomersGrants(t *testing.T) {
	// on the example customers as they are, everyone outside a legacy group
	// may do exactly what the estate intends, and nobody in one loses read
	// on anything they should read: the legacy style grants more by design,
	// and writes only in the first environment
	for _, name := range customerNames {
		t.Run(name, func(t *testing.T) {
			p, m := generateCustomer(t, name)
			v := viewOf(m)

			for _, person := range p.People {
				legacy := person.Group != nil && person.Group.Style == estate.StyleLegacy
				if person.OpsManager != nil {
					for _, g := range person.OpsManager.Groups {
						legacy = legacy || g.Style == estate.StyleLegacy
					}
				}

				got := v.personAccess(person.Name)
				if !legacy {
					require.Equal(t, p.Access(person), got, "%s (%s)", person.Name, person.Kind)

					continue
				}

				for ref, ops := range p.Access(person) {
					require.True(t, got[ref].Read || !ops.Read, "%s lost read on %v", person.Name, ref)
				}
			}
		})
	}
}

func TestExampleCustomersCoverTheVariance(t *testing.T) {
	var (
		kubeClusters, awsAccounts, mixedModels int
		awsArrangements                        = map[string]bool{}
		identity                               = map[bool]bool{}
		styles                                 = map[string]bool{}
		userpassAt                             = map[string]bool{}
	)

	for _, name := range customerNames {
		p, m := generateCustomer(t, name)
		identity[m.Identity] = true

		for _, model := range p.Models {
			// count the Kubernetes and AWS mounts the manifest really has for
			// the model, not just the setting
			k8s, aws := map[string]bool{}, map[string]bool{}
			for _, pm := range authMounts(m) {
				switch {
				case pm.Type == TypeKubernetes && strings.HasPrefix(pm.Path, "k8s-"+model.Name+"-"):
					k8s[pm.Path] = true
				case pm.Type == TypeAWS && (pm.Path == "aws-"+model.Name || strings.HasPrefix(pm.Path, "aws-"+model.Name+"-")):
					aws[pm.Path] = true
					for _, cw := range pm.Config {
						if strings.HasPrefix(cw.Path, "config/sts/") {
							awsArrangements["shared"] = true
						}
					}
				}
			}

			if len(k8s) > 1 {
				kubeClusters++
			}

			if len(p.AWSAccounts[model.Name]) > 1 && len(aws) > 0 {
				awsAccounts++
				if len(aws) > 1 {
					awsArrangements["per-account"] = true
				}
			}

			modelStyles := map[string]bool{}
			for _, g := range p.Groups {
				if g.Model == model.Name {
					modelStyles[g.Style] = true
					styles[g.Style] = true
				}
			}

			if len(modelStyles) > 1 {
				mixedModels++
			}
		}

		if m.Edition == estate.EditionEnterprise {
			for _, pm := range authMounts(m) {
				if pm.Type != TypeUserpass {
					continue
				}

				switch {
				case pm.Namespace == "":
					userpassAt["root"] = true
				case !strings.Contains(pm.Namespace, "/"):
					userpassAt["unit"] = true
				}
			}
		}
	}

	require.Positive(t, kubeClusters, "a model with more than one Kubernetes cluster")
	require.Positive(t, awsAccounts, "a model with more than one AWS account")
	require.Equal(t, map[string]bool{"shared": true, "per-account": true}, awsArrangements)
	require.Equal(t, map[bool]bool{true: true, false: true}, identity, "identity on and off")
	require.Equal(t, map[string]bool{"per-app": true, "templated": true, "legacy": true}, styles)
	require.Positive(t, mixedModels, "a model mixing styles")
	require.Equal(t, map[string]bool{"root": true, "unit": true}, userpassAt, "people's logins at the root and in a unit")
}

func TestOneStylePerGroup(t *testing.T) {
	for _, name := range customerNames {
		p, m := generateCustomer(t, name)

		style := map[string]string{}
		for _, g := range p.Groups {
			style[g.Name] = g.Style
		}

		// every policy carries its group's style
		policies := 0
		for _, pols := range policiesByName(m) {
			for _, pol := range pols {
				policies++
				require.Equal(t, style[pol.Group], pol.Style, "%s: %s of %s", name, pol.Name, pol.Group)
			}
		}

		require.Positive(t, policies, name)

		// and every app's and person's policies are their group's
		byName := policiesByName(m)
		groupOf := func(pname string) string { return byName[pname][0].Group }

		for _, a := range p.Apps {
			for _, r := range rolesByApp(m)[AppID(a)] {
				for _, pname := range r.Policies {
					require.Equal(t, a.Group.Style, style[groupOf(pname)], "%s: %s on %s", name, pname, AppID(a))
				}
			}
		}

		v := viewOf(m)
		for _, person := range p.People {
			if person.Group == nil {
				continue
			}

			for _, u := range v.users[person.Name] {
				for _, pname := range u.Policies {
					require.Equal(t, person.Group.Style, style[groupOf(pname)], "%s: %s on %s", name, pname, person.Name)
				}
			}

			for _, grp := range v.groups {
				for _, mem := range grp.Members {
					if mem.Entity != person.Name {
						continue
					}

					for _, pname := range grp.Policies {
						require.Equal(t, person.Group.Style, style[groupOf(pname)], "%s: %s through %s on %s", name, pname, grp.Name, person.Name)
					}
				}
			}
		}
	}
}
