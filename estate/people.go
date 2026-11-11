package estate

import (
	"fmt"
	"math/rand/v2"
)

// The kinds of person. Everyone logs in with a username and password.
const (
	KindDeveloper  = "developer"
	KindTester     = "tester"
	KindPM         = "pm"
	KindManager    = "manager"
	KindOps        = "ops"
	KindOpsManager = "ops-manager"
)

// Person is someone who logs in to Vault with a username and password.
type Person struct {
	// Name is the person's username, unique within the customer, i.e.
	// checkout-dev-3, checkout-tester or commerce-ops-2.
	Name string
	Kind string
	// Team is a developer's, tester's or PM's team.
	Team *Node
	// Group is the ops group a manager or ops engineer looks after, and the
	// one a developer's, tester's or PM's team is in.
	Group *OpsGroup
	// OpsManager is an ops manager's own entry.
	OpsManager *OpsManager
}

// OpsGroup is the up to Span teams under one manager, together with that
// manager and two ops engineers who look after the group's teams and apps.
// It carries one policy style.
type OpsGroup struct {
	// Name is the manager's node name, i.e. commerce, or cto in an org
	// small enough for the teams to sit under the CTO.
	Name string
	// Manager is the teams' parent in the org.
	Manager *Node
	Teams   []*Node
	// ManagerPerson is the manager's login.
	ManagerPerson *Person
	Ops           []*Person
	OpsManager    *OpsManager
	// Model is the model holding most of the group's apps, and Style the
	// policy style the group's teams, apps and people share.
	Model, Style string
}

// OpsManager is responsible for up to Span ops groups, with the combined
// access of their ops engineers.
type OpsManager struct {
	Person *Person
	Groups []*OpsGroup
}

// opsPerGroup is how many ops engineers look after an ops group.
const opsPerGroup = 2

// developers is how many developers a team has, weighted so most teams have
// 6 to 8 and the median across a customer's teams is 6, while sizes still
// range from 2 to 8.
var developers = []struct{ n, weight int }{
	{2, 2}, {3, 3}, {4, 5}, {5, 10}, {6, 40}, {7, 25}, {8, 15},
}

// buildPeople works out the org's ops groups, ops managers and people: each
// team's parent manager forms an ops group with its teams, the groups are
// gathered Span at a time, in org order, under ops managers, and each team
// gets its developers, a tester and a PM. It draws from its own stream, so
// the rest of the estate doesn't move.
func buildPeople(r *rand.Rand, org *Node) ([]*OpsGroup, []*OpsManager, []*Person) {
	var groups []*OpsGroup

	byManager := map[*Node]*OpsGroup{}
	for _, team := range org.Teams() {
		g := byManager[team.Parent]
		if g == nil {
			g = &OpsGroup{Name: team.Parent.Name, Manager: team.Parent}
			byManager[team.Parent] = g
			groups = append(groups, g)
		}

		g.Teams = append(g.Teams, team)
	}

	var people []*Person
	for _, g := range groups {
		g.ManagerPerson = &Person{Name: g.Name + "-manager", Kind: KindManager, Group: g}
		people = append(people, g.ManagerPerson)

		for i := range opsPerGroup {
			ops := &Person{Name: fmt.Sprintf("%s-ops-%d", g.Name, i+1), Kind: KindOps, Group: g}
			g.Ops = append(g.Ops, ops)
			people = append(people, ops)
		}

		for _, team := range g.Teams {
			for i := range developerCount(r) {
				people = append(people, &Person{Name: fmt.Sprintf("%s-dev-%d", team.Name, i+1), Kind: KindDeveloper, Team: team, Group: g})
			}

			people = append(people,
				&Person{Name: team.Name + "-tester", Kind: KindTester, Team: team, Group: g},
				&Person{Name: team.Name + "-pm", Kind: KindPM, Team: team, Group: g},
			)
		}
	}

	var managers []*OpsManager
	for i := 0; i < len(groups); i += Span {
		om := &OpsManager{Groups: groups[i:min(i+Span, len(groups))]}
		om.Person = &Person{Name: fmt.Sprintf("ops-manager-%d", len(managers)+1), Kind: KindOpsManager, OpsManager: om}

		for _, g := range om.Groups {
			g.OpsManager = om
		}

		managers = append(managers, om)
		people = append(people, om.Person)
	}

	return groups, managers, people
}

// developerCount draws a team's number of developers.
func developerCount(r *rand.Rand) int {
	total := 0
	for _, d := range developers {
		total += d.weight
	}

	x := r.IntN(total)
	for _, d := range developers {
		if x < d.weight {
			return d.n
		}

		x -= d.weight
	}

	return developers[len(developers)-1].n
}

// Group returns the ops group a team is in.
func (p *Plan) Group(team *Node) *OpsGroup {
	for _, g := range p.Groups {
		if g.Manager == team.Parent {
			return g
		}
	}

	return nil
}
