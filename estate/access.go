package estate

import "slices"

// Access is a simple example of who may use an app's secrets. It is
// deliberately simpler than a real estate: a few kinds of principal, the
// same rules in every environment.
//
//	app         the app itself
//	developers  the developers in the app's team
//	testers     the team's tester, who reads its configuration and API keys
//	managers    the manager of the app's ops group, who reads everything
//	            belonging to the group's teams
//	ops         the ops engineers of the app's ops group, who look after its
//	            databases
//
// A database has three credentials, one per database role (read, read-write
// and admin); each kind of principal gets the one it needs, and ops, who
// rotate them, can write all three. PMs have no access, and an ops manager
// has the combined access of the ops engineers in their groups.

// Who is a kind of principal.
type Who string

const (
	WhoApp        Who = "app"
	WhoDevelopers Who = "developers"
	WhoTesters    Who = "testers"
	WhoManagers   Who = "managers"
	WhoOps        Who = "ops"
)

// Whos are the kinds of principal, in the order grants are listed.
var Whos = []Who{WhoApp, WhoDevelopers, WhoTesters, WhoManagers, WhoOps}

// Ops is what a principal may do with a secret.
type Ops struct {
	Read  bool
	Write bool
}

// String is r, w, rw or -.
func (o Ops) String() string {
	switch {
	case o.Read && o.Write:
		return "rw"
	case o.Read:
		return "r"
	case o.Write:
		return "w"
	default:
		return "-"
	}
}

var (
	read      = Ops{Read: true}
	readWrite = Ops{Read: true, Write: true}
)

// AccessRules are who may do what with each of an app's secrets, by
// thing/secret.
// Managers aren't listed: they read every secret of their group's teams.
var AccessRules = map[string]map[Who]Ops{
	"config/settings": {WhoApp: read, WhoDevelopers: readWrite, WhoTesters: read, WhoOps: read},
	"api/key":         {WhoApp: read, WhoDevelopers: readWrite, WhoTesters: read},
	"db/read":         {WhoDevelopers: read, WhoOps: readWrite},
	"db/read-write":   {WhoApp: read, WhoOps: readWrite},
	"db/admin":        {WhoOps: readWrite},
}

// Grant is one principal's access to a secret.
type Grant struct {
	Who Who
	// Principal names the principal: the app, the team's developers
	// (<team>-developers) or testers (<team>-testers), or the ops group's
	// manager (<group>-manager) or ops engineers (<group>-ops).
	Principal string
	Ops       Ops
}

// Grants returns who may use the secret, in the order of Whos.
func (s Secret) Grants() []Grant {
	rules := AccessRules[s.Thing+"/"+s.Name]

	var gs []Grant
	for _, w := range Whos {
		ops, ok := rules[w]
		if w == WhoManagers {
			ops, ok = read, true
		}

		if !ok {
			continue
		}

		gs = append(gs, Grant{Who: w, Principal: principal(s.App, w), Ops: ops})
	}

	return gs
}

// principal names who w is for the app.
func principal(a *App, w Who) string {
	switch w {
	case WhoDevelopers:
		return a.Team.Name + "-developers"
	case WhoTesters:
		return a.Team.Name + "-testers"
	case WhoManagers:
		return a.Team.Parent.Name + "-manager"
	case WhoOps:
		return a.Team.Parent.Name + "-ops"
	default:
		return a.Name
	}
}

// SecretRef says where a secret sits.
type SecretRef struct {
	Cluster, Namespace, Mount, Path string
}

// Access returns what the person may do with each secret they can use, as
// the estate intends: a developer's or tester's from their team's grants, a
// manager's or ops engineer's from their group's, and an ops manager's the
// combined access of their groups' ops engineers. A PM has none.
func (p *Plan) Access(person *Person) map[SecretRef]Ops {
	// who the person is, and whether a secret's app is theirs
	var whos []Who
	mine := func(a *App) bool { return false }

	switch person.Kind {
	case KindDeveloper, KindTester:
		whos = []Who{WhoDevelopers}
		if person.Kind == KindTester {
			whos = []Who{WhoTesters}
		}

		mine = func(a *App) bool { return a.Team == person.Team }
	case KindManager, KindOps:
		whos = []Who{WhoManagers}
		if person.Kind == KindOps {
			whos = []Who{WhoOps}
		}

		mine = func(a *App) bool { return a.Team.Parent == person.Group.Manager }
	case KindOpsManager:
		whos = []Who{WhoOps}
		mine = func(a *App) bool {
			for _, g := range person.OpsManager.Groups {
				if a.Team.Parent == g.Manager {
					return true
				}
			}

			return false
		}
	}

	out := map[SecretRef]Ops{}
	for _, c := range p.Clusters {
		for _, ns := range c.Namespaces {
			for _, m := range ns.Mounts {
				for _, sec := range m.Secrets {
					if !mine(sec.App) {
						continue
					}

					for _, g := range sec.Grants() {
						if !slices.Contains(whos, g.Who) {
							continue
						}

						ref := SecretRef{c.Name, ns.Path, m.Path, sec.Path()}
						ops := out[ref]
						out[ref] = Ops{Read: ops.Read || g.Ops.Read, Write: ops.Write || g.Ops.Write}
					}
				}
			}
		}
	}

	return out
}
