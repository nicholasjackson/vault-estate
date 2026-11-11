package vaultapply

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nicholasjackson/vault-estate/estate"
	"github.com/nicholasjackson/vault-estate/manifest"
)

// request is one request the fake Vault received.
type request struct {
	Method    string
	Path      string
	Namespace string
	Token     string
	Body      map[string]any
}

// call is a request's method, path and namespace, for comparing order.
type call struct {
	Method, Path, Namespace string
}

// fakeVault answers like an empty Vault, records every request, and keeps
// the mounts and auth methods enabled so far, per namespace.
type fakeVault struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	requests  []request
	mounts    map[string]map[string]any
	auths     map[string]map[string]any
	accessors int
	// fail are paths that answer 400 {"errors":["boom"]}; 400 so the
	// client does not retry
	fail map[string]bool
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()

	// the client would otherwise send the caller's namespace on every request
	t.Setenv("VAULT_NAMESPACE", "")

	f := &fakeVault{
		t:      t,
		mounts: map[string]map[string]any{},
		auths:  map[string]map[string]any{},
		fail:   map[string]bool{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)

	return f
}

// seedMount pre-enables a secrets engine, as a dev server does secret/.
func (f *fakeVault) seedMount(ns, path, typ, version string) {
	info := map[string]any{"type": typ}
	if version != "" {
		info["options"] = map[string]any{"version": version}
	}

	f.table(f.mounts, ns)[path+"/"] = info
}

// seedAuth pre-enables an auth method.
func (f *fakeVault) seedAuth(ns, path, typ, accessor string) {
	f.table(f.auths, ns)[path+"/"] = map[string]any{"type": typ, "accessor": accessor}
}

func (f *fakeVault) table(t map[string]map[string]any, ns string) map[string]any {
	if t[ns] == nil {
		t[ns] = map[string]any{}
	}

	return t[ns]
}

func (f *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Errorf("reading body: %v", err)
	}

	var body map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			f.t.Errorf("decoding body %q: %v", raw, err)
		}
	}

	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	ns := r.Header.Get("X-Vault-Namespace")
	f.requests = append(f.requests, request{
		Method: r.Method, Path: path, Namespace: ns,
		Token: r.Header.Get("X-Vault-Token"), Body: body,
	})

	if f.fail[path] {
		reply(w, http.StatusBadRequest, map[string]any{"errors": []string{"boom"}})
		return
	}

	switch {
	case r.Method == http.MethodGet && path == "sys/mounts":
		reply(w, http.StatusOK, map[string]any{"data": f.table(f.mounts, ns)})

	case r.Method == http.MethodGet && path == "sys/auth":
		reply(w, http.StatusOK, map[string]any{"data": f.table(f.auths, ns)})

	case r.Method == http.MethodGet:
		reply(w, http.StatusNotFound, map[string]any{"errors": []string{}})

	case strings.HasPrefix(path, "sys/mounts/"):
		mount := strings.TrimPrefix(path, "sys/mounts/")
		mounts := f.table(f.mounts, ns)
		if _, ok := mounts[mount+"/"]; ok {
			reply(w, http.StatusBadRequest, map[string]any{"errors": []string{"path is already in use at " + mount + "/"}})
			return
		}

		mounts[mount+"/"] = map[string]any{"type": body["type"], "options": body["options"]}
		w.WriteHeader(http.StatusNoContent)

	case strings.HasPrefix(path, "sys/auth/"):
		mount := strings.TrimPrefix(path, "sys/auth/")
		auths := f.table(f.auths, ns)
		if _, ok := auths[mount+"/"]; ok {
			reply(w, http.StatusBadRequest, map[string]any{"errors": []string{"path is already in use at " + mount + "/"}})
			return
		}

		f.accessors++
		typ, _ := body["type"].(string)
		auths[mount+"/"] = map[string]any{"type": typ, "accessor": fmt.Sprintf("auth_%s_%d", typ, f.accessors)}
		w.WriteHeader(http.StatusNoContent)

	case path == "identity/entity":
		reply(w, http.StatusOK, map[string]any{"data": map[string]any{"id": entityID(ns, body["name"])}})

	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func entityID(ns string, name any) string {
	if ns == "" {
		ns = "root"
	}

	return fmt.Sprintf("id-%s-%v", ns, name)
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// recorded is a copy of the requests so far.
func (f *fakeVault) recorded() []request {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.requests)
}

// calls are the requests' method, path and namespace, leaving out the
// secret writes, whose order is not fixed, when withSecrets is false.
func (f *fakeVault) calls(withSecrets bool) []call {
	var out []call
	for _, r := range f.recorded() {
		if !withSecrets && isSecret(r.Path) {
			continue
		}

		out = append(out, call{r.Method, r.Path, r.Namespace})
	}

	return out
}

func isSecret(path string) bool {
	return strings.Contains(path, "/data/")
}

// find is the one request to path in the namespace.
func (f *fakeVault) find(t *testing.T, method, path, ns string) request {
	t.Helper()

	var found []request
	for _, r := range f.recorded() {
		if r.Method == method && r.Path == path && r.Namespace == ns {
			found = append(found, r)
		}
	}

	require.Len(t, found, 1, "%s %s in %q", method, path, ns)

	return found[0]
}

func apply(f *fakeVault, m *manifest.Manifest) error {
	return Apply(context.Background(), m, Options{Addrs: map[string]string{m.Clusters[0].Name: f.srv.URL}, Token: "root"})
}

// estateManifest is a root, a child "a" and a grandchild "a/b", using every
// kind of object: the root and "a" both have a userpass mount, so their
// accessors differ.
func estateManifest() *manifest.Manifest {
	return &manifest.Manifest{
		Customer: "acme",
		Clusters: []manifest.Cluster{{
			Name: "c1",
			Namespaces: []manifest.Namespace{
				{
					Path: "",
					SecretMounts: []manifest.SecretMount{{
						Path:    "secret",
						Secrets: []manifest.Secret{{Path: "app/db", Data: map[string]string{"password": "p1"}}},
					}},
					AuthMounts: []manifest.AuthMount{{
						Path: "userpass", Type: "userpass",
						Users: []manifest.User{{Name: "alice", Password: "pw", Policies: []string{"dev"}}},
					}},
					Policies: []manifest.Policy{{Name: "dev", Text: `path "secret/*" { capabilities = ["read"] }`}},
					Entities: []manifest.Entity{{
						Name:     "alice",
						Metadata: map[string]string{"team": "t1"},
						Aliases:  []manifest.Alias{{Name: "alice", Mount: "userpass", CustomMetadata: map[string]string{"kind": "person"}}},
					}},
				},
				{
					Path: "a",
					SecretMounts: []manifest.SecretMount{{
						Path: "kv",
						Secrets: []manifest.Secret{
							{Path: "svc/api", Data: map[string]string{"key": "k1"}},
							{Path: "svc/web", Data: map[string]string{"key": "k2", "user": "u"}},
						},
					}},
					AuthMounts: []manifest.AuthMount{
						{
							Path: "userpass", Type: "userpass",
							Users: []manifest.User{{Name: "bob", Password: "pw2"}},
						},
						{
							Path: "kubernetes", Type: "kubernetes",
							Config: []manifest.ConfigWrite{{Path: "config", Data: map[string]any{"kubernetes_host": "https://k8s"}}},
							Roles: []manifest.Role{{
								Name:     "api",
								Config:   map[string]any{"bound_service_account_names": []string{"api"}, "token_ttl": "1h"},
								Policies: []string{"api"},
							}},
						},
						{
							Path: "approle", Type: "approle",
							Roles: []manifest.Role{{
								Name:             "legacy",
								Config:           map[string]any{"token_ttl": "1h"},
								Policies:         []string{"legacy"},
								SecretIDMetadata: map[string]string{"app": "team-api"},
							}},
						},
					},
					Policies: []manifest.Policy{{
						Name: "api",
						Text: `path "kv/{{identity.entity.aliases.${accessor:userpass}.name}}" {}` + "\n" +
							`path "kv/{{identity.entity.aliases.${accessor:kubernetes}.metadata.ns}}" {}`,
					}},
					Entities: []manifest.Entity{{
						Name:    "bob",
						Aliases: []manifest.Alias{{Name: "bob", Mount: "userpass"}},
					}},
					Groups: []manifest.IdentityGroup{{
						Name:     "ops",
						Policies: []string{"api"},
						Members:  []manifest.MemberRef{{Namespace: "", Entity: "alice"}, {Namespace: "a", Entity: "bob"}},
					}},
				},
				{
					Path:         "a/b",
					SecretMounts: []manifest.SecretMount{{Path: "kv", Secrets: []manifest.Secret{{Path: "deep", Data: map[string]string{"x": "y"}}}}},
					Policies:     []manifest.Policy{{Name: "deep", Text: `path "kv/*" {}`}},
				},
			},
		}},
	}
}

func TestApplyWritesEveryObjectInPhaseOrder(t *testing.T) {
	f := newFakeVault(t)

	require.NoError(t, apply(f, estateManifest()))

	require.Equal(t, []call{
		// namespaces, each in its parent
		{"POST", "sys/namespaces/a", ""},
		{"POST", "sys/namespaces/b", "a"},
		// secret mounts
		{"POST", "sys/mounts/secret", ""},
		{"POST", "sys/mounts/kv", "a"},
		{"POST", "sys/mounts/kv", "a/b"},
		// auth mounts, then their accessors
		{"POST", "sys/auth/userpass", ""},
		{"GET", "sys/auth", ""},
		{"POST", "sys/auth/userpass", "a"},
		{"POST", "sys/auth/kubernetes", "a"},
		{"POST", "sys/auth/approle", "a"},
		{"GET", "sys/auth", "a"},
		// auth config
		{"POST", "auth/kubernetes/config", "a"},
		// policies
		{"POST", "sys/policies/acl/dev", ""},
		{"POST", "sys/policies/acl/api", "a"},
		{"POST", "sys/policies/acl/deep", "a/b"},
		// roles and users
		{"POST", "auth/userpass/users/alice", ""},
		{"POST", "auth/userpass/users/bob", "a"},
		{"POST", "auth/kubernetes/role/api", "a"},
		{"POST", "auth/approle/role/legacy", "a"},
		{"POST", "auth/approle/role/legacy/secret-id", "a"},
		// entities and aliases
		{"POST", "identity/entity", ""},
		{"POST", "identity/entity-alias", ""},
		{"POST", "identity/entity", "a"},
		{"POST", "identity/entity-alias", "a"},
		// groups
		{"POST", "identity/group", "a"},
	}, f.calls(false)[:25])

	// the secrets come last, in any order
	all := f.calls(true)
	require.Len(t, all, 29)
	require.ElementsMatch(t, []call{
		{"POST", "secret/data/app/db", ""},
		{"POST", "kv/data/svc/api", "a"},
		{"POST", "kv/data/svc/web", "a"},
		{"POST", "kv/data/deep", "a/b"},
	}, all[25:])

	for _, r := range f.recorded() {
		require.Equal(t, "root", r.Token, r.Path)
	}

	require.Equal(t, map[string]any{"type": "kv", "options": map[string]any{"version": "2"}}, f.find(t, "POST", "sys/mounts/kv", "a/b").Body)
	require.Equal(t, map[string]any{"type": "kubernetes"}, f.find(t, "POST", "sys/auth/kubernetes", "a").Body)
	require.Equal(t, map[string]any{"kubernetes_host": "https://k8s"}, f.find(t, "POST", "auth/kubernetes/config", "a").Body)
	require.Equal(t, map[string]any{"policy": `path "secret/*" { capabilities = ["read"] }`}, f.find(t, "POST", "sys/policies/acl/dev", "").Body)

	require.Equal(t, map[string]any{"password": "pw", "token_policies": []any{"dev"}}, f.find(t, "POST", "auth/userpass/users/alice", "").Body)
	require.Equal(t, map[string]any{"password": "pw2", "token_policies": []any{}}, f.find(t, "POST", "auth/userpass/users/bob", "a").Body)
	require.Equal(t, map[string]any{
		"bound_service_account_names": []any{"api"},
		"token_ttl":                   "1h",
		"token_policies":              []any{"api"},
	}, f.find(t, "POST", "auth/kubernetes/role/api", "a").Body)
	require.Equal(t, map[string]any{"token_ttl": "1h", "token_policies": []any{"legacy"}}, f.find(t, "POST", "auth/approle/role/legacy", "a").Body)
	require.Equal(t, map[string]any{"metadata": `{"app":"team-api"}`}, f.find(t, "POST", "auth/approle/role/legacy/secret-id", "a").Body)

	require.Equal(t, map[string]any{"name": "alice", "metadata": map[string]any{"team": "t1"}}, f.find(t, "POST", "identity/entity", "").Body)
	require.Equal(t, map[string]any{"name": "bob"}, f.find(t, "POST", "identity/entity", "a").Body)
	require.Equal(t, map[string]any{
		"name": "alice", "canonical_id": "id-root-alice", "mount_accessor": "auth_userpass_1",
		"custom_metadata": map[string]any{"kind": "person"},
	}, f.find(t, "POST", "identity/entity-alias", "").Body)
	require.Equal(t, map[string]any{
		"name": "bob", "canonical_id": "id-a-bob", "mount_accessor": "auth_userpass_2",
	}, f.find(t, "POST", "identity/entity-alias", "a").Body)

	// a member from the namespace above resolves to its entity there
	require.Equal(t, map[string]any{
		"name": "ops", "type": "internal", "policies": []any{"api"},
		"member_entity_ids": []any{"id-root-alice", "id-a-bob"},
	}, f.find(t, "POST", "identity/group", "a").Body)

	require.Equal(t, map[string]any{"data": map[string]any{"password": "p1"}}, f.find(t, "POST", "secret/data/app/db", "").Body)
	require.Equal(t, map[string]any{"data": map[string]any{"key": "k2", "user": "u"}}, f.find(t, "POST", "kv/data/svc/web", "a").Body)
	require.Equal(t, map[string]any{"data": map[string]any{"x": "y"}}, f.find(t, "POST", "kv/data/deep", "a/b").Body)
}

func TestApplyReplacesAccessorPlaceholdersWithTheNamespacesMount(t *testing.T) {
	f := newFakeVault(t)

	require.NoError(t, apply(f, estateManifest()))

	// "a"'s userpass is auth_userpass_2, not the root's auth_userpass_1
	require.Equal(t, map[string]any{
		"policy": `path "kv/{{identity.entity.aliases.auth_userpass_2.name}}" {}` + "\n" +
			`path "kv/{{identity.entity.aliases.auth_kubernetes_3.metadata.ns}}" {}`,
	}, f.find(t, "POST", "sys/policies/acl/api", "a").Body)

	for _, r := range f.recorded() {
		if strings.HasPrefix(r.Path, "sys/policies/acl/") {
			require.NotContains(t, r.Body["policy"], "${accessor:", r.Path)
		}
	}
}

func TestApplyRejectsAPlaceholderNamingNoMount(t *testing.T) {
	f := newFakeVault(t)

	m := &manifest.Manifest{Clusters: []manifest.Cluster{{
		Name: "c1",
		Namespaces: []manifest.Namespace{
			{Path: ""},
			{
				Path:       "team",
				AuthMounts: []manifest.AuthMount{{Path: "userpass", Type: "userpass"}},
				Policies:   []manifest.Policy{{Name: "p", Text: `path "x/{{identity.entity.aliases.${accessor:approle}.name}}" {}`}},
			},
		},
	}}}

	err := apply(f, m)
	require.ErrorContains(t, err, `cluster c1 namespace "team": policy p: no auth mount approle`)

	for _, r := range f.recorded() {
		require.NotEqual(t, "sys/policies/acl/p", r.Path)
	}
}

func TestApplySendsTheNamespaceHeaderOnlyOutsideTheRoot(t *testing.T) {
	f := newFakeVault(t)

	require.NoError(t, apply(f, estateManifest()))

	require.Equal(t, "", f.find(t, "POST", "sys/policies/acl/dev", "").Namespace)
	require.Equal(t, "a/b", f.find(t, "POST", "sys/policies/acl/deep", "a/b").Namespace)

	namespaces := map[string]bool{}
	for _, r := range f.recorded() {
		namespaces[r.Namespace] = true
	}

	require.Equal(t, map[string]bool{"": true, "a": true, "a/b": true}, namespaces)
}

func TestApplyIgnoresTheEnvironmentsNamespace(t *testing.T) {
	f := newFakeVault(t)

	// a VAULT_NAMESPACE left set in the shell must not move the root's
	// writes into it (the client only reads it with vault.WithEnvironment)
	t.Setenv("VAULT_NAMESPACE", "elsewhere")

	require.NoError(t, apply(f, estateManifest()))

	require.Equal(t, "", f.find(t, "POST", "sys/policies/acl/dev", "").Namespace)
	for _, r := range f.recorded() {
		require.NotEqual(t, "elsewhere", r.Namespace, "%s %s", r.Method, r.Path)
	}
}

func twoClusters() *manifest.Manifest {
	return &manifest.Manifest{Clusters: []manifest.Cluster{
		{Name: "east", Namespaces: []manifest.Namespace{{
			Path:         "",
			SecretMounts: []manifest.SecretMount{{Path: "east-kv", Secrets: []manifest.Secret{{Path: "s", Data: map[string]string{"k": "e"}}}}},
			Policies:     []manifest.Policy{{Name: "east-policy", Text: "east"}},
		}}},
		{Name: "west", Namespaces: []manifest.Namespace{{
			Path:         "",
			SecretMounts: []manifest.SecretMount{{Path: "west-kv", Secrets: []manifest.Secret{{Path: "s", Data: map[string]string{"k": "w"}}}}},
			Policies:     []manifest.Policy{{Name: "west-policy", Text: "west"}},
		}}},
	}}
}

func TestApplyWritesEachClusterToItsOwnAddress(t *testing.T) {
	east, west := newFakeVault(t), newFakeVault(t)

	err := Apply(context.Background(), twoClusters(), Options{
		Addrs: map[string]string{"east": east.srv.URL, "west": west.srv.URL},
		Token: "root",
	})
	require.NoError(t, err)

	require.Equal(t, []call{
		{"POST", "sys/mounts/east-kv", ""},
		{"POST", "sys/policies/acl/east-policy", ""},
		{"POST", "east-kv/data/s", ""},
	}, east.calls(true))

	require.Equal(t, []call{
		{"POST", "sys/mounts/west-kv", ""},
		{"POST", "sys/policies/acl/west-policy", ""},
		{"POST", "west-kv/data/s", ""},
	}, west.calls(true))
}

func TestApplyChecksEveryAddressBeforeWriting(t *testing.T) {
	east, west := newFakeVault(t), newFakeVault(t)

	err := Apply(context.Background(), twoClusters(), Options{
		Addrs: map[string]string{"east": east.srv.URL},
		Token: "root",
	})
	require.ErrorContains(t, err, "no address for cluster west")
	require.Empty(t, east.recorded())
	require.Empty(t, west.recorded())

	err = Apply(context.Background(), twoClusters(), Options{
		Addrs: map[string]string{"east": east.srv.URL, "west": west.srv.URL, "north": west.srv.URL},
		Token: "root",
	})
	require.ErrorContains(t, err, "the manifest has no cluster north")
	require.Empty(t, east.recorded())
	require.Empty(t, west.recorded())
}

// devManifest writes a secret into secret/ and logs in with userpass, in
// the root or in a namespace.
func devManifest(ns string) *manifest.Manifest {
	namespaces := []manifest.Namespace{{Path: ""}}
	if ns != "" {
		namespaces = append(namespaces, manifest.Namespace{Path: ns})
	}

	last := &namespaces[len(namespaces)-1]
	last.SecretMounts = []manifest.SecretMount{{Path: "secret", Secrets: []manifest.Secret{{Path: "app", Data: map[string]string{"k": "v"}}}}}
	last.AuthMounts = []manifest.AuthMount{{Path: "userpass", Type: "userpass", Users: []manifest.User{{Name: "u", Password: "p"}}}}
	last.Policies = []manifest.Policy{{Name: "p", Text: `path "{{identity.entity.aliases.${accessor:userpass}.name}}" {}`}}

	return &manifest.Manifest{Clusters: []manifest.Cluster{{Name: "dev", Namespaces: namespaces}}}
}

func TestApplyReusesAMountOfTheSameType(t *testing.T) {
	f := newFakeVault(t)
	f.seedMount("", "secret", "kv", "2")
	f.seedAuth("", "userpass", "userpass", "auth_userpass_dev")

	require.NoError(t, apply(f, devManifest("")))

	require.Equal(t, map[string]any{"data": map[string]any{"k": "v"}}, f.find(t, "POST", "secret/data/app", "").Body)
	require.Equal(t, map[string]any{"policy": `path "{{identity.entity.aliases.auth_userpass_dev.name}}" {}`}, f.find(t, "POST", "sys/policies/acl/p", "").Body)
}

func TestApplyRejectsAMountOfAnotherType(t *testing.T) {
	for _, tc := range []struct {
		name string
		ns   string
		seed func(f *fakeVault, ns string)
		want string
	}{
		{
			name: "kv v1 in the root",
			seed: func(f *fakeVault, ns string) { f.seedMount(ns, "secret", "kv", "1") },
			want: `cluster dev namespace "": mount secret: already mounted as kv (version "1"), not kv (version "2")`,
		},
		{
			name: "another engine in a namespace",
			ns:   "team",
			seed: func(f *fakeVault, ns string) { f.seedMount(ns, "secret", "cubbyhole", "") },
			want: `cluster dev namespace "team": mount secret: already mounted as cubbyhole`,
		},
		{
			name: "another auth method in a namespace",
			ns:   "team/sub",
			seed: func(f *fakeVault, ns string) { f.seedAuth(ns, "userpass", "ldap", "auth_ldap_x") },
			want: `cluster dev namespace "team/sub": mount userpass: already mounted as ldap`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeVault(t)
			tc.seed(f, tc.ns)

			m := devManifest(tc.ns)
			if tc.ns == "team/sub" {
				m.Clusters[0].Namespaces = slices.Insert(m.Clusters[0].Namespaces, 1, manifest.Namespace{Path: "team"})
			}

			require.ErrorContains(t, apply(f, m), tc.want)

			for _, r := range f.recorded() {
				require.False(t, strings.HasPrefix(r.Path, "sys/policies/"), "no policy after a failed mount: %s", r.Path)
				require.False(t, isSecret(r.Path), "no secret after a failed mount: %s", r.Path)
			}
		})
	}
}

func TestApplyStopsAtTheFirstFailedWrite(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail string
		want string
	}{
		{
			name: "namespace",
			fail: "sys/namespaces/b",
			want: `cluster c1 namespace "a": namespace a/b: 400 Bad Request: boom`,
		},
		{
			name: "auth config",
			fail: "auth/kubernetes/config",
			want: `cluster c1 namespace "a": auth config kubernetes/config: 400 Bad Request: boom`,
		},
		{
			name: "policy",
			fail: "sys/policies/acl/dev",
			want: `cluster c1 namespace "": policy dev: 400 Bad Request: boom`,
		},
		{
			name: "role",
			fail: "auth/kubernetes/role/api",
			want: `cluster c1 namespace "a": role kubernetes/api: 400 Bad Request: boom`,
		},
		{
			name: "secret id",
			fail: "auth/approle/role/legacy/secret-id",
			want: `cluster c1 namespace "a": role approle/legacy secret-id: 400 Bad Request: boom`,
		},
		{
			name: "user",
			fail: "auth/userpass/users/alice",
			want: `cluster c1 namespace "": user userpass/alice: 400 Bad Request: boom`,
		},
		{
			name: "entity alias",
			fail: "identity/entity-alias",
			want: `cluster c1 namespace "": entity alice alias alice: 400 Bad Request: boom`,
		},
		{
			name: "group",
			fail: "identity/group",
			want: `cluster c1 namespace "a": group ops: 400 Bad Request: boom`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeVault(t)
			f.fail[tc.fail] = true

			require.ErrorContains(t, apply(f, estateManifest()), tc.want)

			// the failed write was the last request
			got := f.recorded()
			require.Equal(t, tc.fail, got[len(got)-1].Path)

			for _, r := range got {
				require.False(t, isSecret(r.Path), "no secret after a failed %s: %s", tc.name, r.Path)
			}
		})
	}
}

func TestApplyStopsAtAFailedSecret(t *testing.T) {
	f := newFakeVault(t)
	f.fail["kv/data/svc/web"] = true

	require.ErrorContains(t, apply(f, estateManifest()), `cluster c1 namespace "a": secret kv/svc/web: 400 Bad Request: boom`)
}

func TestApplyRejectsAGroupMemberWithNoEntity(t *testing.T) {
	f := newFakeVault(t)

	m := estateManifest()
	m.Clusters[0].Namespaces[1].Groups[0].Members = append(m.Clusters[0].Namespaces[1].Groups[0].Members, manifest.MemberRef{Namespace: "a/b", Entity: "carol"})

	require.ErrorContains(t, apply(f, m), `cluster c1 namespace "a": group ops: no entity carol in namespace "a/b"`)

	for _, r := range f.recorded() {
		require.NotEqual(t, "identity/group", r.Path)
	}
}

// TestApplyAGeneratedManifest applies a generated enterprise estate with
// namespaces and identity.
func TestApplyAGeneratedManifest(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cluster.xcl"), []byte(`
cluster "smoke" {
  edition  = "enterprise"
  identity = true

  model "apps" {
    apps      = 6
    namespace = "per-app"
    platforms = { kubernetes = "50%", vm = "50%" }
  }
}
`), 0o600))

	cfgs, err := estate.Load(dir)
	require.NoError(t, err)
	require.Len(t, cfgs, 1)

	p, err := estate.Build(cfgs[0])
	require.NoError(t, err)

	m, err := manifest.Generate(p)
	require.NoError(t, err)
	require.Len(t, m.Clusters, 1)

	f := newFakeVault(t)
	f.seedMount("", "secret", "kv", "2")

	require.NoError(t, apply(f, m))

	created := map[string]bool{}
	secrets, writes := 0, 0
	for _, r := range f.recorded() {
		require.Equal(t, "root", r.Token)

		if strings.HasPrefix(r.Path, "sys/namespaces/") {
			created[strings.Trim(r.Namespace+"/"+strings.TrimPrefix(r.Path, "sys/namespaces/"), "/")] = true
		}

		if strings.HasPrefix(r.Path, "sys/policies/acl/") {
			require.NotContains(t, r.Body["policy"], "${accessor:", r.Path)
		}

		if isSecret(r.Path) {
			writes++
		}
	}

	for _, ns := range m.Clusters[0].Namespaces {
		if ns.Path != "" {
			require.True(t, created[ns.Path], "namespace %s", ns.Path)
		}

		for _, sm := range ns.SecretMounts {
			secrets += len(sm.Secrets)
		}
	}

	require.Positive(t, secrets)
	require.NotEmpty(t, created)
	require.True(t, slices.ContainsFunc(f.recorded(), func(r request) bool { return r.Path == "identity/entity-alias" }), "identity is written")
	require.Equal(t, secrets, writes)
	require.Len(t, created, len(m.Clusters[0].Namespaces)-1)
}
