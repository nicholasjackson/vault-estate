// Package vaultapply applies a manifest (manifest) to one empty Vault
// per cluster, through vault-client-go's generic requests. It writes in
// fixed phases, resolving what only Vault knows as it goes: mount
// accessors for the policies' ${accessor:<mount>} placeholders and alias
// mounts, and entity IDs for group members. It never deletes anything, and
// reuses a mount that already exists with the same type, such as a dev
// server's secret/.
package vaultapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/hashicorp/vault-client-go"

	"github.com/nicholasjackson/vault-estate/manifest"
)

// Options say where each cluster's Vault is and how to write to it.
type Options struct {
	// Addrs are each cluster's Vault address, by cluster name.
	Addrs map[string]string
	// Token is used for every cluster.
	Token string
	// Workers is how many secrets are written at once; 8 by default.
	Workers int
}

// Apply writes the manifest to its clusters, one after another. It checks
// every cluster has an address, and no address names a cluster the
// manifest doesn't have, before writing anything.
func Apply(ctx context.Context, m *manifest.Manifest, o Options) error {
	if err := checkAddrs(m, o.Addrs); err != nil {
		return err
	}

	if o.Workers < 1 {
		o.Workers = 8
	}

	for _, c := range m.Clusters {
		// no WithEnvironment: the manifest names every namespace itself, so a
		// VAULT_NAMESPACE left in the shell mustn't move the root's writes
		client, err := vault.New(vault.WithAddress(o.Addrs[c.Name]))
		if err == nil {
			err = client.SetToken(o.Token)
		}

		if err != nil {
			return fmt.Errorf("cluster %s: %w", c.Name, err)
		}

		a := &applier{
			client: client, cluster: c.Name, workers: o.Workers,
			accessors: map[string]string{}, entities: map[string]string{},
		}

		if err := a.apply(ctx, c); err != nil {
			return err
		}
	}

	return nil
}

// checkAddrs reports the clusters with no address and the addresses for
// clusters the manifest doesn't have.
func checkAddrs(m *manifest.Manifest, addrs map[string]string) error {
	var missing, unknown []string

	names := map[string]bool{}
	for _, c := range m.Clusters {
		names[c.Name] = true
		if addrs[c.Name] == "" {
			missing = append(missing, c.Name)
		}
	}

	for name := range addrs {
		if !names[name] {
			unknown = append(unknown, name)
		}
	}

	slices.Sort(unknown)

	var errs []error
	if len(missing) > 0 {
		errs = append(errs, fmt.Errorf("no address for cluster %s: give one with -addr <cluster>=<url>", strings.Join(missing, ", ")))
	}

	if len(unknown) > 0 {
		errs = append(errs, fmt.Errorf("the manifest has no cluster %s", strings.Join(unknown, ", ")))
	}

	return errors.Join(errs...)
}

// applier writes one cluster.
type applier struct {
	client  *vault.Client
	cluster string
	workers int

	// accessors are the auth mounts' accessors, and entities the entities'
	// IDs, by key(namespace, name)
	accessors map[string]string
	entities  map[string]string
}

func key(ns, name string) string {
	return ns + "|" + name
}

// apply writes the cluster in phases, each over every namespace, parents
// first, so later phases can name what earlier ones made.
func (a *applier) apply(ctx context.Context, c manifest.Cluster) error {
	phases := []func(context.Context, manifest.Namespace) error{
		a.namespace,
		a.secretMounts,
		a.authMounts,
		a.authConfig,
		a.policies,
		a.logins,
		a.identity,
		a.groups,
	}

	for _, phase := range phases {
		for _, ns := range c.Namespaces {
			if err := phase(ctx, ns); err != nil {
				return err
			}
		}
	}

	return a.secrets(ctx, c)
}

// write writes data at path in the namespace, and wraps any error with
// where it was and what was being written.
func (a *applier) write(ctx context.Context, ns, what, path string, data map[string]any) (*vault.Response[map[string]any], error) {
	resp, err := a.client.Write(ctx, path, data, a.in(ns)...)
	if err != nil {
		return nil, a.fail(ns, what, err)
	}

	return resp, nil
}

func (a *applier) fail(ns, what string, err error) error {
	return fmt.Errorf("cluster %s namespace %q: %s: %w", a.cluster, ns, what, err)
}

// in are the request options for the namespace: none for the root.
func (a *applier) in(ns string) []vault.RequestOption {
	if ns == "" {
		return nil
	}

	return []vault.RequestOption{vault.WithNamespace(ns)}
}

// namespace creates the namespace in its parent; the manifest lists
// parents first.
func (a *applier) namespace(ctx context.Context, ns manifest.Namespace) error {
	if ns.Path == "" {
		return nil
	}

	parent, child := "", ns.Path
	if i := strings.LastIndex(ns.Path, "/"); i >= 0 {
		parent, child = ns.Path[:i], ns.Path[i+1:]
	}

	_, err := a.write(ctx, parent, "namespace "+ns.Path, "sys/namespaces/"+child, nil)

	return err
}

// secretMounts enables the namespace's KV v2 mounts.
func (a *applier) secretMounts(ctx context.Context, ns manifest.Namespace) error {
	for _, m := range ns.SecretMounts {
		if err := a.mount(ctx, ns.Path, "sys/mounts", m.Path, "kv", "2"); err != nil {
			return err
		}
	}

	return nil
}

// authMounts enables the namespace's auth methods, and records each one's
// accessor.
func (a *applier) authMounts(ctx context.Context, ns manifest.Namespace) error {
	if len(ns.AuthMounts) == 0 {
		return nil
	}

	for _, m := range ns.AuthMounts {
		if err := a.mount(ctx, ns.Path, "sys/auth", m.Path, m.Type, ""); err != nil {
			return err
		}
	}

	resp, err := a.client.Read(ctx, "sys/auth", a.in(ns.Path)...)
	if err != nil {
		return a.fail(ns.Path, "reading auth mounts", err)
	}

	for _, m := range ns.AuthMounts {
		accessor := ""
		if resp != nil {
			if info, ok := resp.Data[m.Path+"/"].(map[string]any); ok {
				accessor, _ = info["accessor"].(string)
			}
		}

		if accessor == "" {
			return a.fail(ns.Path, "auth mount "+m.Path, errors.New("no accessor in sys/auth"))
		}

		a.accessors[key(ns.Path, m.Path)] = accessor
	}

	return nil
}

// mount enables a secrets engine or auth method at path. A mount already
// there is reused when it has the same type (and KV version); any other is
// an error.
func (a *applier) mount(ctx context.Context, ns, sys, path, typ, version string) error {
	what := "mount " + path
	body := map[string]any{"type": typ}
	if version != "" {
		body["options"] = map[string]any{"version": version}
	}

	_, err := a.client.Write(ctx, sys+"/"+path, body, a.in(ns)...)
	if err == nil {
		return nil
	}

	var re *vault.ResponseError
	if !errors.As(err, &re) || !slices.ContainsFunc(re.Errors, func(e string) bool { return strings.Contains(e, "already in use") }) {
		return a.fail(ns, what, err)
	}

	resp, rerr := a.client.Read(ctx, sys, a.in(ns)...)
	if rerr != nil {
		return a.fail(ns, what, rerr)
	}

	var info map[string]any
	if resp != nil {
		info, _ = resp.Data[path+"/"].(map[string]any)
	}

	have, _ := info["type"].(string)
	haveVersion := ""
	if opts, ok := info["options"].(map[string]any); ok {
		haveVersion, _ = opts["version"].(string)
	}

	if have != typ || (version != "" && haveVersion != version) {
		return a.fail(ns, what, fmt.Errorf("already mounted as %s (version %q), not %s (version %q)", have, haveVersion, typ, version))
	}

	return nil
}

// authConfig writes the auth methods' configuration.
func (a *applier) authConfig(ctx context.Context, ns manifest.Namespace) error {
	for _, m := range ns.AuthMounts {
		for _, cw := range m.Config {
			if _, err := a.write(ctx, ns.Path, "auth config "+m.Path+"/"+cw.Path, "auth/"+m.Path+"/"+cw.Path, cw.Data); err != nil {
				return err
			}
		}
	}

	return nil
}

var accessorPlaceholder = regexp.MustCompile(`\$\{accessor:([^}]+)\}`)

// policies writes the namespace's policies, with each ${accessor:<mount>}
// replaced by that mount's accessor in the same namespace.
func (a *applier) policies(ctx context.Context, ns manifest.Namespace) error {
	for _, p := range ns.Policies {
		var missing error
		text := accessorPlaceholder.ReplaceAllStringFunc(p.Text, func(placeholder string) string {
			mount := accessorPlaceholder.FindStringSubmatch(placeholder)[1]
			accessor, ok := a.accessors[key(ns.Path, mount)]
			if !ok {
				missing = fmt.Errorf("no auth mount %s for its template", mount)
			}

			return accessor
		})

		if missing != nil {
			return a.fail(ns.Path, "policy "+p.Name, missing)
		}

		if _, err := a.write(ctx, ns.Path, "policy "+p.Name, "sys/policies/acl/"+p.Name, map[string]any{"policy": text}); err != nil {
			return err
		}
	}

	return nil
}

// logins writes the roles and users, with their policies, and a SecretID
// carrying its metadata for every AppRole role whose policy is templated
// from it.
func (a *applier) logins(ctx context.Context, ns manifest.Namespace) error {
	for _, m := range ns.AuthMounts {
		for _, r := range m.Roles {
			body := map[string]any{}
			for k, v := range r.Config {
				body[k] = v
			}

			body["token_policies"] = policyList(r.Policies)

			what := "role " + m.Path + "/" + r.Name
			if _, err := a.write(ctx, ns.Path, what, "auth/"+m.Path+"/role/"+r.Name, body); err != nil {
				return err
			}

			if len(r.SecretIDMetadata) > 0 {
				meta, err := json.Marshal(r.SecretIDMetadata)
				if err != nil {
					return a.fail(ns.Path, what, err)
				}

				if _, err := a.write(ctx, ns.Path, what+" secret-id", "auth/"+m.Path+"/role/"+r.Name+"/secret-id", map[string]any{"metadata": string(meta)}); err != nil {
					return err
				}
			}
		}

		for _, u := range m.Users {
			body := map[string]any{"password": u.Password, "token_policies": policyList(u.Policies)}
			if _, err := a.write(ctx, ns.Path, "user "+m.Path+"/"+u.Name, "auth/"+m.Path+"/users/"+u.Name, body); err != nil {
				return err
			}
		}
	}

	return nil
}

// policyList is the policies as Vault takes them: never null.
func policyList(names []string) []string {
	if names == nil {
		return []string{}
	}

	return names
}

// identity writes the namespace's entities and their aliases, recording
// each entity's ID.
func (a *applier) identity(ctx context.Context, ns manifest.Namespace) error {
	for _, e := range ns.Entities {
		what := "entity " + e.Name
		body := map[string]any{"name": e.Name}
		if len(e.Metadata) > 0 {
			body["metadata"] = e.Metadata
		}

		resp, err := a.write(ctx, ns.Path, what, "identity/entity", body)
		if err != nil {
			return err
		}

		id := ""
		if resp != nil {
			id, _ = resp.Data["id"].(string)
		}

		// writing an entity that is already there updates it and says
		// nothing, so look it up
		if id == "" {
			got, err := a.client.Read(ctx, "identity/entity/name/"+e.Name, a.in(ns.Path)...)
			if err != nil {
				return a.fail(ns.Path, what, err)
			}

			if got != nil {
				id, _ = got.Data["id"].(string)
			}
		}

		if id == "" {
			return a.fail(ns.Path, what, errors.New("no entity ID"))
		}

		a.entities[key(ns.Path, e.Name)] = id

		for _, al := range e.Aliases {
			accessor, ok := a.accessors[key(ns.Path, al.Mount)]
			if !ok {
				return a.fail(ns.Path, what, fmt.Errorf("no auth mount %s for alias %s", al.Mount, al.Name))
			}

			body := map[string]any{"name": al.Name, "canonical_id": id, "mount_accessor": accessor}
			if len(al.CustomMetadata) > 0 {
				body["custom_metadata"] = al.CustomMetadata
			}

			if _, err := a.write(ctx, ns.Path, what+" alias "+al.Name, "identity/entity-alias", body); err != nil {
				return err
			}
		}
	}

	return nil
}

// groups writes the namespace's internal groups, with their members'
// entity IDs, from this namespace or one above it.
func (a *applier) groups(ctx context.Context, ns manifest.Namespace) error {
	for _, g := range ns.Groups {
		what := "group " + g.Name

		ids := []string{}
		for _, m := range g.Members {
			id, ok := a.entities[key(m.Namespace, m.Entity)]
			if !ok {
				return a.fail(ns.Path, what, fmt.Errorf("no entity %s in namespace %q", m.Entity, m.Namespace))
			}

			ids = append(ids, id)
		}

		body := map[string]any{"name": g.Name, "type": "internal", "policies": policyList(g.Policies), "member_entity_ids": ids}
		if _, err := a.write(ctx, ns.Path, what, "identity/group", body); err != nil {
			return err
		}
	}

	return nil
}

// secrets writes every secret in the cluster through a pool of workers,
// stopping at the first failure.
func (a *applier) secrets(ctx context.Context, c manifest.Cluster) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type job struct {
		ns, mount string
		secret    manifest.Secret
	}

	jobs := make(chan job)

	var (
		wg    sync.WaitGroup
		once  sync.Once
		first error
	)

	for range a.workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for j := range jobs {
				data := map[string]any{}
				for k, v := range j.secret.Data {
					data[k] = v
				}

				what := "secret " + j.mount + "/" + j.secret.Path
				if _, err := a.write(ctx, j.ns, what, j.mount+"/data/"+j.secret.Path, map[string]any{"data": data}); err != nil {
					once.Do(func() {
						first = err
						cancel()
					})
				}
			}
		}()
	}

send:
	for _, ns := range c.Namespaces {
		for _, m := range ns.SecretMounts {
			for _, sec := range m.Secrets {
				select {
				case jobs <- job{ns.Path, m.Path, sec}:
				case <-ctx.Done():
					break send
				}
			}
		}
	}

	close(jobs)
	wg.Wait()

	if first != nil {
		return first
	}

	return ctx.Err()
}
