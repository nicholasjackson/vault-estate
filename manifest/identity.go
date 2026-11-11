package manifest

import (
	"slices"

	"github.com/nicholasjackson/vault-estate/estate"
)

// personEntities gives every person, when the customer manages identity, an
// entity in each place they log in, with an alias on that place's userpass
// mount. People's policies then come through internal groups (see
// groupMember) rather than their logins.
func (g *generator) personEntities() {
	for _, person := range g.plan.People {
		meta := map[string]string{"kind": person.Kind}
		if person.Team != nil {
			meta["team"] = person.Team.Name
		}

		if person.Group != nil {
			meta["group"] = person.Group.Name
		}

		for _, at := range g.loginScopes(person) {
			g.entities[at] = append(g.entities[at], Entity{
				Name:     person.Name,
				Metadata: meta,
				Aliases:  []Alias{{Name: person.Name, Mount: userpassMount}},
			})
		}
	}
}

// groupMember puts the person's entity in the login scope into the internal
// group called name in the scope, which carries the policy.
func (g *generator) groupMember(at scope, name, policy string, login scope, person *estate.Person) {
	if g.groups[at] == nil {
		g.groups[at] = map[string]*IdentityGroup{}
	}

	grp := g.groups[at][name]
	if grp == nil {
		grp = &IdentityGroup{Name: name}
		g.groups[at][name] = grp
	}

	if !slices.Contains(grp.Policies, policy) {
		grp.Policies = append(grp.Policies, policy)
	}

	ref := MemberRef{Namespace: login.Namespace, Entity: person.Name}
	for _, m := range grp.Members {
		if m == ref {
			return
		}
	}

	grp.Members = append(grp.Members, ref)
}
