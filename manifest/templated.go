package manifest

import (
	"slices"

	"github.com/nicholasjackson/vault-estate/estate"
)

// templated writes an ops group's policies in the identity-templated style:
//
//   - apps: one policy per auth mount the group's apps log in through,
//     <group>-<mount>, whose team and app path segments are filled in at
//     login from the app's identity (Kubernetes service-account metadata,
//     AppRole SecretID metadata, or a pre-created AWS alias's custom
//     metadata), shared by every app on the mount
//   - ops: <group>-ops, with + for team, app and environment
//   - people, with identity: <group>-developers-templated and
//     <group>-testers-templated, filled in from the entity's team, through
//     the groups <group>-developers and <group>-testers, and a wildcard
//     <group>-manager; without identity, the tidy people policies
//
// A shared legacy AppRole in the group keeps tidy policies for its apps.
// Templates name auth mounts as ${accessor:<mount>}, which apply fills in.
func (g *generator) templated(group *estate.OpsGroup) {
	type mountKey struct {
		at   scope
		path string
	}

	var mounts []mountKey
	apps := map[mountKey][]*estate.App{}

	for _, team := range group.Teams {
		for _, a := range team.Apps {
			if a.Platform == estate.PlatformLegacy {
				g.appPolicies(group, a)

				continue
			}

			role := g.roleOf[a]
			k := mountKey{role.scope, role.Mount}
			if apps[k] == nil {
				mounts = append(mounts, k)
			}

			apps[k] = append(apps[k], a)
		}
	}

	for _, k := range mounts {
		mount := g.authMount(k.at, k.path, "")
		name := group.Name + "-" + k.path

		var team, app string
		switch mount.Type {
		case TypeKubernetes:
			team, app = aliasMeta(k.path, "metadata.service_account_namespace"), aliasMeta(k.path, "metadata.service_account_name")
		case TypeAWS:
			team, app = aliasMeta(k.path, "custom_metadata.team"), aliasMeta(k.path, "custom_metadata.app")

			// an IAM login carries no app identity, so each Lambda app's alias
			// is made ahead, named by its role's full ARN
			if !slices.ContainsFunc(mount.Config, func(c ConfigWrite) bool { return c.Path == "config/identity" }) {
				mount.Config = append(mount.Config, ConfigWrite{Path: "config/identity", Data: map[string]any{"iam_alias": "full_arn"}})
			}
		default:
			team, app = aliasMeta(k.path, "metadata.team"), aliasMeta(k.path, "metadata.app")
		}

		p := newPolicy(name, group.Style, group.Name, nil)
		for _, a := range apps[k] {
			at := g.placed[a]
			for _, sec := range g.secretsOf[a] {
				for _, gr := range sec.Grants() {
					if gr.Who == estate.WhoApp {
						path := pattern(sec, map[string]string{"team": team, "app": app, "env": "+"})
						p.addRule(Rule{Path: dataPath(at.Mount, path), Capabilities: caps(gr.Ops)})
					}
				}
			}

			role := g.roleOf[a]
			g.rolePolicies[role] = append(g.rolePolicies[role], name)

			switch mount.Type {
			case TypeAppRole:
				g.secretIDMeta[role] = map[string]string{"team": a.Team.Name, "app": a.Name}
			case TypeAWS:
				g.entities[k.at] = append(g.entities[k.at], Entity{
					Name: AppID(a),
					Aliases: []Alias{{
						Name: lambdaRoleARN(a), Mount: k.path,
						CustomMetadata: map[string]string{"team": a.Team.Name, "app": a.Name},
					}},
				})
			}
		}

		p.Text = renderHCL(p.Rules)
		g.addPolicy(k.at, p)
	}

	// The ops and manager wildcards only replace the team, app and
	// environment segments. The org folders above the team stay literal, and
	// they end with the group's manager, so a wildcard never reaches another
	// group's secrets on a shared mount. Where a namespace captures the
	// manager's level instead, the namespace holds only this group's teams.
	anySegment := map[string]string{"team": "+", "app": "+", "env": "+"}
	wildcard := func(sec estate.Secret) string { return pattern(sec, anySegment) }

	people := []peoplePolicy{opsPolicy(group, wildcard)}
	if !g.plan.Identity {
		for _, pp := range tidyPeople(group) {
			if pp.Who != estate.WhoOps {
				people = append(people, pp)
			}
		}
	} else {
		byTeam := func(sec estate.Secret) string {
			return pattern(sec, map[string]string{"team": "{{identity.entity.metadata.team}}", "app": "+", "env": "+"})
		}

		people = append(people,
			peoplePolicy{Name: group.Name + "-developers-templated", IdentityGroup: group.Name + "-developers", Who: estate.WhoDevelopers, Teams: group.Teams, Path: byTeam, Member: groupKind(group, estate.KindDeveloper)},
			peoplePolicy{Name: group.Name + "-testers-templated", IdentityGroup: group.Name + "-testers", Who: estate.WhoTesters, Teams: group.Teams, Path: byTeam, Member: groupKind(group, estate.KindTester)},
			peoplePolicy{Name: group.Name + "-manager", Who: estate.WhoManagers, Teams: group.Teams, Path: wildcard, Member: groupKind(group, estate.KindManager)},
		)
	}

	for _, pp := range people {
		g.peoplePolicy(group, pp)
	}
}

// aliasMeta is a template for a value of the login's alias on the auth
// mount, i.e. metadata.service_account_name.
func aliasMeta(mount, key string) string {
	return "{{identity.entity.aliases.${accessor:" + mount + "}." + key + "}}"
}
