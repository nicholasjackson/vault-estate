package manifest

import (
	"fmt"
	"slices"
	"sort"

	"github.com/nicholasjackson/vault-estate/estate"
)

// Generate describes the estate's Vault configuration. It does no I/O and
// draws only from streams seeded from the customer's seed, so the same
// estate always gives the same manifest.
func Generate(p *estate.Plan) (*Manifest, error) {
	g := &generator{
		plan:         p,
		values:       newValues(p.Seed),
		placed:       placements(p),
		secretsOf:    secretsOf(p),
		auth:         map[scope]map[string]*AuthMount{},
		roleOf:       map[*estate.App]roleRef{},
		policies:     map[scope]map[string]*Policy{},
		rolePolicies: map[roleRef][]string{},
		userPolicies: map[userRef][]string{},

		secretIDMeta: map[roleRef]map[string]string{},
		entities:     map[scope][]Entity{},
		groups:       map[scope]map[string]*IdentityGroup{},
	}

	m := &Manifest{
		Customer: p.Name,
		Edition:  p.Edition,
		Seed:     p.Seed,
		Identity: p.Identity,
		Org:      org(p),
		Clusters: []Cluster{},
	}

	// the secrets, mirroring the estate's clusters, namespaces and mounts
	for _, c := range p.Clusters {
		mc := Cluster{Name: c.Name, Namespaces: []Namespace{}}

		for _, ns := range c.Namespaces {
			mn := Namespace{Path: ns.Path}

			for _, mt := range ns.Mounts {
				sm := SecretMount{Path: mt.Path, Secrets: []Secret{}}
				for _, sec := range mt.Secrets {
					sm.Secrets = append(sm.Secrets, g.secret(sec))
				}

				mn.SecretMounts = append(mn.SecretMounts, sm)
			}

			mc.Namespaces = append(mc.Namespaces, mn)
		}

		m.Clusters = append(m.Clusters, mc)
	}

	// then the logins, in the namespaces the estate already has
	g.appLogins()
	g.peopleLogins()

	if p.Identity {
		g.personEntities()
	}

	// then each ops group's policies, in its style
	for _, group := range p.Groups {
		switch group.Style {
		case estate.StyleTemplated:
			g.templated(group)
		case estate.StyleLegacy:
			g.legacy(group)
		default:
			g.tidy(group)
		}
	}

	return m, g.attach(m)
}

// generator holds what the builders share while a manifest is generated.
type generator struct {
	plan   *estate.Plan
	values *values
	// placed is where each app's secrets sit
	placed map[*estate.App]placement
	// secretsOf are each app's secrets, in order
	secretsOf map[*estate.App][]estate.Secret
	// auth are the auth mounts built so far, by scope and path
	auth map[scope]map[string]*AuthMount
	// roleOf is the role each app logs in with
	roleOf map[*estate.App]roleRef
	// policies are the policies built so far, by scope and name
	policies map[scope]map[string]*Policy
	// rolePolicies and userPolicies are the policies attached to each role
	// and user
	rolePolicies map[roleRef][]string
	userPolicies map[userRef][]string
	// secretIDMeta is the metadata of the SecretID apply creates for an
	// AppRole role whose policy is templated from it
	secretIDMeta map[roleRef]map[string]string
	// entities and groups are the identity objects built so far, by scope
	entities map[scope][]Entity
	groups   map[scope]map[string]*IdentityGroup
}

// roleRef names a role: its mount's scope and path, and its name.
type roleRef struct {
	scope
	Mount, Name string
}

// userRef names a userpass user in a scope.
type userRef struct {
	scope
	Name string
}

// addPolicy adds the policy to the scope.
func (g *generator) addPolicy(at scope, p *Policy) {
	if g.policies[at] == nil {
		g.policies[at] = map[string]*Policy{}
	}

	g.policies[at][p.Name] = p
}

// addRole adds a role to the mount at path in the scope, and returns where
// it is.
func (g *generator) addRole(at scope, path, typ string, r Role) roleRef {
	mount := g.authMount(at, path, typ)
	mount.Roles = append(mount.Roles, r)

	return roleRef{at, path, r.Name}
}

// secretsOf returns each app's secrets, in the estate's order.
func secretsOf(p *estate.Plan) map[*estate.App][]estate.Secret {
	out := map[*estate.App][]estate.Secret{}
	for _, c := range p.Clusters {
		for _, ns := range c.Namespaces {
			for _, m := range ns.Mounts {
				for _, sec := range m.Secrets {
					out[sec.App] = append(out[sec.App], sec)
				}
			}
		}
	}

	return out
}

// authMount returns the auth mount at path in the scope, adding it with the
// type when it isn't there yet.
func (g *generator) authMount(at scope, path, typ string) *AuthMount {
	if g.auth[at] == nil {
		g.auth[at] = map[string]*AuthMount{}
	}

	mount := g.auth[at][path]
	if mount == nil {
		mount = &AuthMount{Path: path, Type: typ}
		g.auth[at][path] = mount
	}

	return mount
}

// attach puts what the builders made into the manifest's namespaces, in a
// fixed order: mounts by path, then roles and users by name.
func (g *generator) attach(m *Manifest) error {
	namespaces := map[scope]*Namespace{}
	for i := range m.Clusters {
		c := &m.Clusters[i]
		for j := range c.Namespaces {
			namespaces[scope{c.Name, c.Namespaces[j].Path}] = &c.Namespaces[j]
		}
	}

	for at, mounts := range g.auth {
		ns := namespaces[at]
		if ns == nil {
			return fmt.Errorf("cluster %s has no namespace %q for its logins", at.Cluster, at.Namespace)
		}

		for _, mount := range mounts {
			for i := range mount.Roles {
				ref := roleRef{at, mount.Path, mount.Roles[i].Name}
				mount.Roles[i].Policies = sorted(g.rolePolicies[ref])
				mount.Roles[i].SecretIDMetadata = g.secretIDMeta[ref]
			}

			for i := range mount.Users {
				mount.Users[i].Policies = sorted(g.userPolicies[userRef{at, mount.Users[i].Name}])
			}

			sort.Slice(mount.Roles, func(i, j int) bool { return mount.Roles[i].Name < mount.Roles[j].Name })
			sort.Slice(mount.Users, func(i, j int) bool { return mount.Users[i].Name < mount.Users[j].Name })
			ns.AuthMounts = append(ns.AuthMounts, *mount)
		}

		sort.Slice(ns.AuthMounts, func(i, j int) bool { return ns.AuthMounts[i].Path < ns.AuthMounts[j].Path })
	}

	for at, byName := range g.policies {
		ns := namespaces[at]
		if ns == nil {
			return fmt.Errorf("cluster %s has no namespace %q for its policies", at.Cluster, at.Namespace)
		}

		for _, p := range byName {
			ns.Policies = append(ns.Policies, *p)
		}

		sort.Slice(ns.Policies, func(i, j int) bool { return ns.Policies[i].Name < ns.Policies[j].Name })
	}

	for at, entities := range g.entities {
		ns := namespaces[at]
		if ns == nil {
			return fmt.Errorf("cluster %s has no namespace %q for its entities", at.Cluster, at.Namespace)
		}

		ns.Entities = append(ns.Entities, entities...)
		sort.Slice(ns.Entities, func(i, j int) bool { return ns.Entities[i].Name < ns.Entities[j].Name })
	}

	for at, byName := range g.groups {
		ns := namespaces[at]
		if ns == nil {
			return fmt.Errorf("cluster %s has no namespace %q for its groups", at.Cluster, at.Namespace)
		}

		for _, grp := range byName {
			sort.Slice(grp.Members, func(i, j int) bool {
				if grp.Members[i].Namespace != grp.Members[j].Namespace {
					return grp.Members[i].Namespace < grp.Members[j].Namespace
				}

				return grp.Members[i].Entity < grp.Members[j].Entity
			})
			ns.Groups = append(ns.Groups, *grp)
		}

		sort.Slice(ns.Groups, func(i, j int) bool { return ns.Groups[i].Name < ns.Groups[j].Name })
	}

	return nil
}

// sorted returns a sorted copy of the names, nil when there are none.
func sorted(names []string) []string {
	if len(names) == 0 {
		return nil
	}

	out := slices.Clone(names)
	slices.Sort(out)

	return slices.Compact(out)
}

func (g *generator) secret(sec estate.Secret) Secret {
	return Secret{
		Path:  sec.Path(),
		App:   AppID(sec.App),
		Team:  sec.App.Team.Name,
		Env:   sec.Env,
		Thing: sec.Thing,
		Name:  sec.Name,
		Data:  g.values.secret(sec),
	}
}

// AppID names an app uniquely within its customer, <team>-<app>: app names
// are only unique within their team.
func AppID(a *estate.App) string {
	return a.Team.Name + "-" + a.Name
}

// org summarises the estate's ops groups, ops managers and people.
func org(p *estate.Plan) Org {
	o := Org{Groups: []Group{}, OpsManagers: []OpsManager{}, People: []Person{}}

	for _, g := range p.Groups {
		mg := Group{
			Name: g.Name, Manager: g.ManagerPerson.Name, OpsManager: g.OpsManager.Person.Name,
			Model: g.Model, Style: g.Style, Ops: []string{}, Teams: []string{},
		}

		for _, ops := range g.Ops {
			mg.Ops = append(mg.Ops, ops.Name)
		}

		for _, t := range g.Teams {
			mg.Teams = append(mg.Teams, t.Name)
		}

		o.Groups = append(o.Groups, mg)
	}

	for _, om := range p.OpsManagers {
		mo := OpsManager{Name: om.Person.Name, Groups: []string{}}
		for _, g := range om.Groups {
			mo.Groups = append(mo.Groups, g.Name)
		}

		o.OpsManagers = append(o.OpsManagers, mo)
	}

	for _, person := range p.People {
		mp := Person{Name: person.Name, Kind: person.Kind}
		if person.Team != nil {
			mp.Team = person.Team.Name
		}

		if person.Group != nil {
			mp.Group = person.Group.Name
		}

		o.People = append(o.People, mp)
	}

	return o
}
