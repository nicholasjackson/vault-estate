package manifest

import (
	"slices"

	"github.com/nicholasjackson/vault-estate/estate"
)

// tidy writes an ops group's policies in the tidy per-app style, granting
// exactly the estate's access, path by path:
//
//   - one policy per app and environment, <team>-<app>-<env>, on the app's
//     login (an ops group's shared legacy AppRole carries each of its apps')
//   - one per team role, <team>-developers and <team>-testers
//   - one for the group's manager, <group>-manager, and one for its ops
//     engineers, <group>-ops, which its ops manager gets too
//
// A policy sits in the namespace of the login it's attached to and reaches
// secrets in namespaces below by their relative path. When the customer
// manages identity, people's policies sit with the secrets instead, and
// come to people through internal groups there whose members are the
// people's entities where they log in.
func (g *generator) tidy(group *estate.OpsGroup) {
	for _, team := range group.Teams {
		for _, a := range team.Apps {
			g.appPolicies(group, a)
		}
	}

	g.peoplePolicies(group)
}

// appPolicies writes an app's policy for each environment, from its app
// grants, where its login is, and attaches them to the login.
func (g *generator) appPolicies(group *estate.OpsGroup, a *estate.App) {
	role := g.roleOf[a]
	at := g.placed[a]
	rel := relPrefix(role.Namespace, at.Namespace)

	var envs []string
	rules := map[string][]Rule{}
	for _, sec := range g.secretsOf[a] {
		for _, gr := range sec.Grants() {
			if gr.Who != estate.WhoApp {
				continue
			}

			if _, ok := rules[sec.Env]; !ok {
				envs = append(envs, sec.Env)
			}

			rules[sec.Env] = append(rules[sec.Env], Rule{Path: rel + dataPath(at.Mount, sec.Path()), Capabilities: caps(gr.Ops)})
		}
	}

	for _, env := range envs {
		name := AppID(a)
		if env != "" {
			name += "-" + env
		}

		g.addPolicy(role.scope, newPolicy(name, group.Style, group.Name, rules[env]))
		g.rolePolicies[role] = append(g.rolePolicies[role], name)
	}
}

// peoplePolicies writes the group's tidy team-role, manager and ops
// policies.
func (g *generator) peoplePolicies(group *estate.OpsGroup) {
	for _, pp := range tidyPeople(group) {
		g.peoplePolicy(group, pp)
	}
}

// tidyPeople are the tidy style's people policies: one per team role, and
// one each for the group's manager and its ops engineers, granting exactly
// the estate's paths.
func tidyPeople(group *estate.OpsGroup) []peoplePolicy {
	var out []peoplePolicy
	for _, team := range group.Teams {
		out = append(out,
			peoplePolicy{Name: team.Name + "-developers", Who: estate.WhoDevelopers, Teams: []*estate.Node{team}, Path: literal, Member: teamKind(team, estate.KindDeveloper)},
			peoplePolicy{Name: team.Name + "-testers", Who: estate.WhoTesters, Teams: []*estate.Node{team}, Path: literal, Member: teamKind(team, estate.KindTester)},
		)
	}

	return append(out,
		peoplePolicy{Name: group.Name + "-manager", Who: estate.WhoManagers, Teams: group.Teams, Path: literal, Member: groupKind(group, estate.KindManager)},
		opsPolicy(group, literal),
	)
}

// opsPolicy is the policy for the group's ops engineers, which their ops
// manager gets too, with its paths written by path.
func opsPolicy(group *estate.OpsGroup, path func(estate.Secret) string) peoplePolicy {
	return peoplePolicy{
		Name: group.Name + "-ops", Who: estate.WhoOps, Teams: group.Teams, Path: path,
		Member: func(person *estate.Person) bool {
			return person.Kind == estate.KindOps && person.Group == group ||
				person.Kind == estate.KindOpsManager && person.OpsManager == group.OpsManager
		},
	}
}

// peoplePolicy describes a policy for a kind of person: the grants it
// carries, how it writes each secret's path, and who gets it.
type peoplePolicy struct {
	Name string
	// IdentityGroup names the internal group carrying the policy when the
	// customer manages identity; the policy's own name when empty.
	IdentityGroup string
	Who           estate.Who
	Teams         []*estate.Node
	// Path writes a secret's path in its mount: literally, or as a pattern.
	Path   func(estate.Secret) string
	Member func(*estate.Person) bool
	// Rules, when set, writes the rules for every one of the teams' secrets
	// instead of Who's grants and Path, with paths relative to the mount
	// (data/..., metadata/... or a v1-style path); the legacy style's mess.
	Rules func(estate.Secret) []Rule
	// Quirks mark the policy's deliberate mess.
	Quirks []string
}

// rulesFor are the policy's rules for a secret, with paths relative to its
// mount.
func (pp peoplePolicy) rulesFor(sec estate.Secret) []Rule {
	if pp.Rules != nil {
		return pp.Rules(sec)
	}

	var out []Rule
	for _, gr := range sec.Grants() {
		if gr.Who == pp.Who {
			out = append(out, Rule{Path: "data/" + pp.Path(sec), Capabilities: caps(gr.Ops)})
		}
	}

	return out
}

// literal is a secret's own path.
func literal(sec estate.Secret) string {
	return sec.Path()
}

func teamKind(team *estate.Node, kind string) func(*estate.Person) bool {
	return func(person *estate.Person) bool { return person.Kind == kind && person.Team == team }
}

func groupKind(group *estate.OpsGroup, kind string) func(*estate.Person) bool {
	return func(person *estate.Person) bool { return person.Kind == kind && person.Group == group }
}

// principalPlace is where a people's policy sits, and the login scope of
// the people it reaches from there: the same place with identity off.
type principalPlace struct {
	at, login scope
}

// peoplePolicy writes the policy in every place it's needed and gives it to
// its people. Without identity it sits where they log in, reaching down to
// the secrets, and is attached to their logins. With identity it sits with
// the secrets and comes to them through an internal group there.
func (g *generator) peoplePolicy(group *estate.OpsGroup, pp peoplePolicy) {
	var places []principalPlace

	// the teams with secrets each place's policy reaches: a team member only
	// gets the policy where their own team's secrets are, as a policy with
	// no team segment to fill in (an app's own namespace) can't tell teams
	// apart
	teamsAt := map[principalPlace][]*estate.Node{}

	for _, team := range pp.Teams {
		for _, a := range team.Apps {
			at := g.placed[a]
			login := loginScope(g.plan, at.scope, a.Model)

			place := principalPlace{login, login}
			rel := relPrefix(login.Namespace, at.Namespace)
			if g.plan.Identity {
				place.at, rel = at.scope, ""
			}

			if !slices.Contains(places, place) {
				places = append(places, place)
			}

			if !slices.Contains(teamsAt[place], team) {
				teamsAt[place] = append(teamsAt[place], team)
			}

			for _, sec := range g.secretsOf[a] {
				for _, r := range pp.rulesFor(sec) {
					p := g.policies[place.at][pp.Name]
					if p == nil {
						p = newPolicy(pp.Name, group.Style, group.Name, nil)
						p.Quirks = pp.Quirks
						g.addPolicy(place.at, p)
					}

					p.addRule(Rule{Path: rel + at.Mount + "/" + r.Path, Capabilities: r.Capabilities})
				}
			}
		}
	}

	// the text follows the rules, now they're all there
	for _, place := range places {
		if p := g.policies[place.at][pp.Name]; p != nil {
			p.Text = renderHCL(p.Rules)
		}
	}

	identityGroup := pp.IdentityGroup
	if identityGroup == "" {
		identityGroup = pp.Name
	}

	for _, person := range g.plan.People {
		if !pp.Member(person) {
			continue
		}

		logins := g.loginScopes(person)
		for _, place := range places {
			if !slices.Contains(logins, place.login) || g.policies[place.at][pp.Name] == nil {
				continue
			}

			if person.Team != nil && !slices.Contains(teamsAt[place], person.Team) {
				continue
			}

			if g.plan.Identity {
				g.groupMember(place.at, identityGroup, pp.Name, place.login, person)
			} else {
				ref := userRef{place.login, person.Name}
				g.userPolicies[ref] = append(g.userPolicies[ref], pp.Name)
			}
		}
	}
}
