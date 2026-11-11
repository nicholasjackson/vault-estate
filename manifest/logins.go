package manifest

import (
	"fmt"
	"slices"
	"sort"

	"github.com/nicholasjackson/vault-estate/estate"
)

// The auth methods.
const (
	TypeKubernetes = "kubernetes"
	TypeAppRole    = "approle"
	TypeAWS        = "aws"
	TypeUserpass   = "userpass"
)

// The shared mounts every namespace that needs one has: an AppRole mount for
// VM and legacy apps, and a userpass mount for people.
const (
	approleMount  = "approle"
	userpassMount = "userpass"
)

// placeholderCA is a self-signed certificate Vault accepts as a Kubernetes
// cluster's CA without reaching the cluster (knowledge
// gotchas/vault-auth-placeholder-config.md). Made with
//
//	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
//	  -days 36500 -nodes -subj /CN=placeholder-k8s-ca
const placeholderCA = `-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIUfnuOofva6eW4DWcQVkmIWKDxS6MwCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwScGxhY2Vob2xkZXItazhzLWNhMCAXDTI2MTEwNTE0MjY1M1oY
DzIxMjYxMDEyMTQyNjUzWjAdMRswGQYDVQQDDBJwbGFjZWhvbGRlci1rOHMtY2Ew
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARYsAJunW4bAuAvAXxmOMuF1BSCSDaA
taNYV8mBPPbJPyYGvpWU8Ruxm/kcrlO6KwMq1ukDaPSLlqviGtBETY13o1MwUTAd
BgNVHQ4EFgQU5jxzV5YMA6U80lyibyqA3XYaJSgwHwYDVR0jBBgwFoAU5jxzV5YM
A6U80lyibyqA3XYaJSgwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBF
AiAaK12H/w6Ti628LwvEFPrBxNipXLohNJC5yaWpIwiW1gIhAKI4yfeWbVUrOPjD
WMlN6+UoR02FTs/zUdKomjy+It4l
-----END CERTIFICATE-----
`

// LegacyRole names an ops group's shared AppRole role for its legacy apps.
func LegacyRole(group string) string {
	return group + "-legacy"
}

// appLogins gives every app a login of its platform's method in the
// namespace holding its secrets: a Kubernetes role on its cluster's mount,
// an AppRole role, or an AWS IAM role through its model's AWS mount. An ops
// group's legacy apps share one AppRole role per cluster, in the nearest
// namespace above all of them.
func (g *generator) appLogins() {
	p := g.plan

	type legacyKey struct{ group, cluster string }

	legacy := map[legacyKey][]*estate.App{}
	var legacyOrder []legacyKey

	for _, a := range p.Apps {
		at := g.placed[a].scope
		m := p.Model(a.Model)

		switch a.Platform {
		case estate.PlatformKubernetes:
			mount := g.authMount(at, a.KubeCluster, TypeKubernetes)
			if len(mount.Config) == 0 {
				mount.Config = []ConfigWrite{{Path: "config", Data: map[string]any{
					"kubernetes_host":      fmt.Sprintf("https://%s.k8s.example.internal:6443", a.KubeCluster),
					"kubernetes_ca_cert":   placeholderCA,
					"disable_local_ca_jwt": true,
				}}}
			}

			g.roleOf[a] = g.addRole(at, a.KubeCluster, TypeKubernetes, Role{
				Name: AppID(a), Apps: []string{AppID(a)},
				Config: map[string]any{
					"bound_service_account_names":      []any{a.Name},
					"bound_service_account_namespaces": []any{a.Team.Name},
					"audience":                         "vault",
				},
			})

		case estate.PlatformLambda:
			path := "aws-" + m.Name
			accounts := p.AWSAccounts[m.Name]
			if m.AWSMounts == estate.AWSMountsPerAccount {
				path += "-" + a.AWSAccount
				accounts = nil
			}

			mount := g.authMount(at, path, TypeAWS)
			if len(mount.Config) == 0 {
				mount.Config = []ConfigWrite{{Path: "config/client", Data: map[string]any{
					"access_key": "AKIAPLACEHOLDER0000",
					"secret_key": "placeholder",
				}}}

				// a shared mount logs in from every account through an STS
				// role in each
				for _, acct := range accounts {
					mount.Config = append(mount.Config, ConfigWrite{
						Path: "config/sts/" + acct,
						Data: map[string]any{"sts_role": "arn:aws:iam::" + acct + ":role/vault-auth"},
					})
				}
			}

			g.roleOf[a] = g.addRole(at, path, TypeAWS, Role{
				Name: AppID(a), Apps: []string{AppID(a)},
				Config: map[string]any{
					"auth_type":               "iam",
					"bound_iam_principal_arn": []any{lambdaRoleARN(a)},
					"resolve_aws_unique_ids":  false,
				},
			})

		case estate.PlatformLegacy:
			k := legacyKey{a.Group.Name, at.Cluster}
			if legacy[k] == nil {
				legacyOrder = append(legacyOrder, k)
			}

			legacy[k] = append(legacy[k], a)

		default:
			g.roleOf[a] = g.addRole(at, approleMount, TypeAppRole, Role{
				Name: AppID(a), Apps: []string{AppID(a)},
				Config: map[string]any{"token_type": "service"},
			})
		}
	}

	for _, k := range legacyOrder {
		apps := legacy[k]

		var namespaces, ids []string
		for _, a := range apps {
			namespaces = append(namespaces, g.placed[a].Namespace)
			ids = append(ids, AppID(a))
		}

		ref := g.addRole(scope{k.cluster, commonAncestor(namespaces)}, approleMount, TypeAppRole, Role{
			Name: LegacyRole(k.group), Apps: ids,
			Config: map[string]any{"token_type": "service"},
		})

		for _, a := range apps {
			g.roleOf[a] = ref
		}
	}
}

// lambdaRoleARN is the IAM role a Lambda app runs as, named by its app id:
// app names are only unique within a team, and two teams' apps can share
// an account.
func lambdaRoleARN(a *estate.App) string {
	return "arn:aws:iam::" + a.AWSAccount + ":role/" + AppID(a)
}

// peopleLogins gives every person a username and password on the userpass
// mount of every place they log in: wherever people log in for the secrets
// of the teams they belong to or look after.
func (g *generator) peopleLogins() {
	for _, person := range g.plan.People {
		for _, at := range g.loginScopes(person) {
			mount := g.authMount(at, userpassMount, TypeUserpass)
			mount.Users = append(mount.Users, User{Name: person.Name, Password: g.values.password(), Person: person.Name})
		}
	}
}

// loginScopes are the places a person logs in, in a fixed order.
func (g *generator) loginScopes(person *estate.Person) []scope {
	var out []scope
	for _, team := range teams(person) {
		for _, a := range team.Apps {
			at := loginScope(g.plan, g.placed[a].scope, a.Model)
			if !slices.Contains(out, at) {
				out = append(out, at)
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Cluster != out[j].Cluster {
			return out[i].Cluster < out[j].Cluster
		}

		return out[i].Namespace < out[j].Namespace
	})

	return out
}

// teams are the teams whose secrets a person logs in for: their own, their
// group's, or their groups' as an ops manager.
func teams(person *estate.Person) []*estate.Node {
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
