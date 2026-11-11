package vaultapply

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/stretchr/testify/require"

	"github.com/nicholasjackson/vault-estate/estate"
	"github.com/nicholasjackson/vault-estate/manifest"
)

// The integration tests apply the community example customers to
// throwaway dev Vault containers and read Vault back. They need docker, so
// they only run when asked for.

func integration(t *testing.T) {
	t.Helper()

	if os.Getenv("VAULT_ESTATE_INTEGRATION") != "1" {
		t.Skip("set VAULT_ESTATE_INTEGRATION=1 to run against throwaway dev Vault containers (needs docker), or use make integration")
	}
}

// startVault starts a dev Vault container with root token root, waits for
// it to be ready, removes it when the test ends, and returns its address.
func startVault(t *testing.T) string {
	t.Helper()

	image := os.Getenv("VAULT_ESTATE_IMAGE")
	if image == "" {
		image = "hashicorp/vault:latest"
	}

	out, err := exec.Command("docker", "run", "-d", "--rm", "-p", "127.0.0.1::8200", image,
		"server", "-dev", "-dev-root-token-id=root", "-dev-listen-address=0.0.0.0:8200").CombinedOutput()
	require.NoError(t, err, string(out))

	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })

	out, err = exec.Command("docker", "port", id, "8200").CombinedOutput()
	require.NoError(t, err, string(out))

	port := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	addr := "http://127.0.0.1:" + port[strings.LastIndex(port, ":")+1:]

	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := http.Get(addr + "/v1/sys/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return addr
			}
		}

		require.True(t, time.Now().Before(deadline), "vault at %s didn't become ready", addr)
		time.Sleep(250 * time.Millisecond)
	}
}

// generate builds and generates an example customer.
func generate(t *testing.T, name string) *manifest.Manifest {
	t.Helper()

	cfgs, err := estate.Load("../customers")
	require.NoError(t, err)

	for _, c := range cfgs {
		if c.Name() == name {
			p, err := estate.Build(c)
			require.NoError(t, err)

			m, err := manifest.Generate(p)
			require.NoError(t, err)

			return m
		}
	}

	require.FailNow(t, "no customer "+name)

	return nil
}

// client is a root client for the Vault at addr.
func client(t *testing.T, addr string) *vault.Client {
	t.Helper()

	c, err := vault.New(vault.WithAddress(addr))
	require.NoError(t, err)
	require.NoError(t, c.SetToken("root"))

	return c
}

var placeholder = regexp.MustCompile(`\$\{accessor:([^}]+)\}`)

// checkCluster reads the cluster's Vault back and checks it holds what the
// manifest describes: every secret mount with a secret per mount matching
// the manifest, every auth mount with its roles, every user, and every
// policy with the manifest's text, accessors filled in.
func checkCluster(t *testing.T, c *vault.Client, mc manifest.Cluster) {
	t.Helper()

	ctx := context.Background()
	root := mc.Namespaces[0]
	require.Equal(t, "", root.Path, "community: the root only")

	mounts, err := c.Read(ctx, "sys/mounts")
	require.NoError(t, err)

	for _, sm := range root.SecretMounts {
		info, ok := mounts.Data[sm.Path+"/"].(map[string]any)
		require.True(t, ok, "%s: no secret mount %s", mc.Name, sm.Path)
		require.Equal(t, "kv", info["type"])

		// one secret per mount, with the manifest's values
		sec := sm.Secrets[len(sm.Secrets)/2]
		resp, err := c.Read(ctx, sm.Path+"/data/"+sec.Path)
		require.NoError(t, err, "%s: %s/%s", mc.Name, sm.Path, sec.Path)

		got := map[string]string{}
		for k, v := range resp.Data["data"].(map[string]any) {
			got[k] = v.(string)
		}

		require.Equal(t, sec.Data, got, "%s: %s/%s", mc.Name, sm.Path, sec.Path)
	}

	auth, err := c.Read(ctx, "sys/auth")
	require.NoError(t, err)

	accessors := map[string]string{}
	for _, am := range root.AuthMounts {
		info, ok := auth.Data[am.Path+"/"].(map[string]any)
		require.True(t, ok, "%s: no auth mount %s", mc.Name, am.Path)
		require.Equal(t, am.Type, info["type"])
		accessors[am.Path] = info["accessor"].(string)

		for _, r := range am.Roles {
			resp, err := c.Read(ctx, "auth/"+am.Path+"/role/"+r.Name)
			require.NoError(t, err, "%s: role %s/%s", mc.Name, am.Path, r.Name)
			require.ElementsMatch(t, r.Policies, stringList(resp.Data["token_policies"]), "%s: role %s/%s", mc.Name, am.Path, r.Name)
		}

		for _, u := range am.Users {
			resp, err := c.Read(ctx, "auth/"+am.Path+"/users/"+u.Name)
			require.NoError(t, err, "%s: user %s", mc.Name, u.Name)
			require.ElementsMatch(t, u.Policies, stringList(resp.Data["token_policies"]), "%s: user %s", mc.Name, u.Name)
		}
	}

	for _, p := range root.Policies {
		resp, err := c.Read(ctx, "sys/policies/acl/"+p.Name)
		require.NoError(t, err, "%s: policy %s", mc.Name, p.Name)

		want := placeholder.ReplaceAllStringFunc(p.Text, func(s string) string {
			return accessors[placeholder.FindStringSubmatch(s)[1]]
		})

		require.Equal(t, want, resp.Data["policy"], "%s: policy %s", mc.Name, p.Name)
	}
}

// stringList reads a JSON list of strings.
func stringList(v any) []string {
	out := []string{}
	if list, ok := v.([]any); ok {
		for _, s := range list {
			out = append(out, s.(string))
		}
	}

	return out
}

// login logs in as the customer's first developer, and returns their
// userpass user and the token's policies and identity policies.
func login(t *testing.T, c *vault.Client, mc manifest.Cluster) (manifest.User, []string, []string) {
	t.Helper()

	for _, am := range mc.Namespaces[0].AuthMounts {
		if am.Type != "userpass" {
			continue
		}

		for _, u := range am.Users {
			if !regexp.MustCompile(`-dev-\d+$`).MatchString(u.Name) {
				continue
			}

			resp, err := c.Write(context.Background(), "auth/"+am.Path+"/login/"+u.Name, map[string]any{"password": u.Password})
			require.NoError(t, err, "logging in as %s", u.Name)
			require.NotNil(t, resp.Auth)

			return u, resp.Auth.TokenPolicies, resp.Auth.IdentityPolicies
		}
	}

	require.FailNow(t, "no developer in "+mc.Name)

	return manifest.User{}, nil, nil
}

func TestApplyStartup(t *testing.T) {
	integration(t)

	m := generate(t, "startup")
	require.False(t, m.Identity)
	require.Len(t, m.Clusters, 1)

	addr := startVault(t)
	require.NoError(t, Apply(context.Background(), m, Options{Addrs: map[string]string{"startup": addr}, Token: "root"}))

	c := client(t, addr)
	checkCluster(t, c, m.Clusters[0])

	// with identity off, the developer's policies are on the token itself
	u, policies, _ := login(t, c, m.Clusters[0])
	require.NotEmpty(t, u.Policies)
	require.Subset(t, policies, u.Policies)
}

func TestApplyNOTHS(t *testing.T) {
	integration(t)

	m := generate(t, "noths")
	require.True(t, m.Identity)
	require.Len(t, m.Clusters, 1)

	addr := startVault(t)
	require.NoError(t, Apply(context.Background(), m, Options{Addrs: map[string]string{"noths": addr}, Token: "root"}))

	c := client(t, addr)
	mc := m.Clusters[0]
	checkCluster(t, c, mc)

	ctx := context.Background()
	root := mc.Namespaces[0]

	// the entities, by name
	ids := map[string]string{}
	for _, e := range root.Entities {
		resp, err := c.Read(ctx, "identity/entity/name/"+e.Name)
		require.NoError(t, err, "entity %s", e.Name)
		ids[e.Name] = resp.Data["id"].(string)
	}

	require.NotEmpty(t, ids)

	// the groups, with their members and policies
	require.NotEmpty(t, root.Groups)
	for _, g := range root.Groups {
		resp, err := c.Read(ctx, "identity/group/name/"+g.Name)
		require.NoError(t, err, "group %s", g.Name)

		var want []string
		for _, mem := range g.Members {
			want = append(want, ids[mem.Entity])
		}

		require.ElementsMatch(t, want, stringList(resp.Data["member_entity_ids"]), "group %s", g.Name)
		require.ElementsMatch(t, g.Policies, stringList(resp.Data["policies"]), "group %s", g.Name)
	}

	// with identity on, the developer's policies come through their groups
	u, _, identityPolicies := login(t, c, mc)
	require.Empty(t, u.Policies)

	var want []string
	for _, g := range root.Groups {
		if slices.ContainsFunc(g.Members, func(mem manifest.MemberRef) bool { return mem.Entity == u.Person }) {
			want = append(want, g.Policies...)
		}
	}

	require.NotEmpty(t, want)
	require.ElementsMatch(t, want, identityPolicies)
}

func TestApplyScaleup(t *testing.T) {
	integration(t)

	m := generate(t, "scaleup")
	require.Len(t, m.Clusters, 4)

	// one dev Vault per cluster
	addrs := map[string]string{}
	for _, mc := range m.Clusters {
		addrs[mc.Name] = startVault(t)
	}

	require.NoError(t, Apply(context.Background(), m, Options{Addrs: addrs, Token: "root"}))

	for _, mc := range m.Clusters {
		c := client(t, addrs[mc.Name])
		checkCluster(t, c, mc)

		u, policies, _ := login(t, c, mc)
		require.Subset(t, policies, u.Policies, mc.Name)
	}
}
