package estate

import (
	"encoding/json"
	"io"
)

// The JSON view of a plan. A Plan can't be marshalled as it is: its nodes,
// apps and secrets point back at each other, so the view names what they
// point at instead.

type jsonPlan struct {
	Name         string        `json:"name"`
	Edition      string        `json:"edition"`
	Industry     string        `json:"industry"`
	Environments []string      `json:"environments"`
	Identity     bool          `json:"identity"`
	Summary      jsonSummary   `json:"summary"`
	Models       []jsonModel   `json:"models"`
	Org          *jsonNode     `json:"org"`
	Apps         []jsonApp     `json:"apps"`
	Groups       []jsonGroup   `json:"groups"`
	People       []jsonPerson  `json:"people"`
	Clusters     []jsonCluster `json:"clusters"`
}

type jsonGroup struct {
	Name       string   `json:"name"`
	Manager    string   `json:"manager"`
	Teams      []string `json:"teams"`
	Ops        []string `json:"ops"`
	OpsManager string   `json:"ops_manager"`
	Model      string   `json:"model,omitempty"`
	Style      string   `json:"style,omitempty"`
}

type jsonPerson struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Team  string `json:"team,omitempty"`
	Group string `json:"group,omitempty"`
}

type jsonSummary struct {
	Apps     int `json:"apps"`
	Teams    int `json:"teams"`
	People   int `json:"people"`
	OrgDepth int `json:"org_depth"`
	Clusters int `json:"clusters"`
	Mounts   int `json:"mounts"`
	Secrets  int `json:"secrets"`
}

type jsonModel struct {
	Name      string            `json:"name"`
	Apps      int               `json:"apps"`
	Namespace string            `json:"namespace"`
	Env       string            `json:"env"`
	Platforms map[string]string `json:"platforms"`
	Databases string            `json:"databases,omitempty"`

	KubernetesClusters int               `json:"kubernetes_clusters"`
	AWSAccounts        int               `json:"aws_accounts"`
	AWSMounts          string            `json:"aws_mounts"`
	Policies           map[string]string `json:"policies"`
	UserAuth           string            `json:"user_auth"`
	AWSAccountIDs      []string          `json:"aws_account_ids"`
}

type jsonNode struct {
	Name     string      `json:"name"`
	Role     string      `json:"role"`
	Path     string      `json:"path"`
	Apps     []string    `json:"apps,omitempty"`
	Children []*jsonNode `json:"children,omitempty"`
}

type jsonApp struct {
	Name      string `json:"name"`
	Team      string `json:"team"`
	TeamPath  string `json:"team_path"`
	Unit      string `json:"unit"`
	Model     string `json:"model"`
	Platform  string `json:"platform"`
	Database  bool   `json:"database"`
	Namespace string `json:"namespace,omitempty"`

	KubeCluster string `json:"kube_cluster,omitempty"`
	AWSAccount  string `json:"aws_account,omitempty"`
	Group       string `json:"group,omitempty"`
}

type jsonCluster struct {
	Name       string          `json:"name"`
	Edition    string          `json:"edition"`
	Namespaces []jsonNamespace `json:"namespaces"`
}

type jsonNamespace struct {
	Path   string      `json:"path"`
	Mounts []jsonMount `json:"mounts,omitempty"`
}

type jsonMount struct {
	Path    string       `json:"path"`
	Model   string       `json:"model"`
	Apps    []string     `json:"apps"`
	Secrets []jsonSecret `json:"secrets,omitempty"`
}

type jsonSecret struct {
	Path     string      `json:"path"`
	App      string      `json:"app"`
	Team     string      `json:"team"`
	Env      string      `json:"env,omitempty"`
	Thing    string      `json:"thing"`
	Name     string      `json:"name"`
	Segments []Segment   `json:"segments"`
	Grants   []jsonGrant `json:"grants"`
}

type jsonGrant struct {
	Who       Who    `json:"who"`
	Principal string `json:"principal"`
	Ops       string `json:"ops"`
}

// MarshalJSON names a segment's fields in the JSON's style.
func (s Segment) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	}{s.Name, s.Kind})
}

// RenderJSON writes the plan to w as indented JSON: its summary, models,
// org, apps, and each cluster's namespaces, mounts and secrets, as deep as
// o.Level says. Plain has no effect.
func RenderJSON(w io.Writer, p *Plan, o RenderOptions) error {
	depth, err := levelDepth(o.Level)
	if err != nil {
		return err
	}

	out := jsonPlan{
		Name:         p.Name,
		Edition:      p.Edition,
		Industry:     p.Industry,
		Environments: p.Environments,
		Identity:     p.Identity,
		Org:          orgJSON(p.Org),
		Apps:         []jsonApp{},
		Clusters:     []jsonCluster{},
		Summary: jsonSummary{
			Apps:     len(p.Apps),
			Teams:    len(p.Org.Teams()),
			People:   len(p.People),
			OrgDepth: p.Depth(),
			Clusters: len(p.Clusters),
			Secrets:  p.Secrets(),
		},
	}

	for _, m := range p.Models {
		// validated when the plan was built, so this can't fail
		shares, _ := m.policyShares()
		policies := map[string]string{}
		for style, share := range shares {
			policies[style] = formatPercent(share)
		}

		out.Models = append(out.Models, jsonModel{
			Name: m.Name, Apps: m.Apps, Namespace: m.Namespace, Env: m.Env,
			Platforms: m.Platforms, Databases: m.Databases,
			KubernetesClusters: *m.KubernetesClusters, AWSAccounts: *m.AWSAccounts,
			AWSMounts: m.AWSMounts, Policies: policies, UserAuth: m.UserAuth,
			AWSAccountIDs: p.AWSAccounts[m.Name],
		})
	}

	for _, a := range p.Apps {
		out.Apps = append(out.Apps, jsonApp{
			Name: a.Name, Team: a.Team.Name, TeamPath: a.Team.Path(), Unit: a.Team.Unit().Name,
			Model: a.Model, Platform: a.Platform, Database: a.Database, Namespace: a.Namespace,
			KubeCluster: a.KubeCluster, AWSAccount: a.AWSAccount, Group: a.Group.Name,
		})
	}

	for _, g := range p.Groups {
		jg := jsonGroup{Name: g.Name, Manager: g.ManagerPerson.Name, OpsManager: g.OpsManager.Person.Name, Model: g.Model, Style: g.Style}
		for _, t := range g.Teams {
			jg.Teams = append(jg.Teams, t.Name)
		}

		for _, o := range g.Ops {
			jg.Ops = append(jg.Ops, o.Name)
		}

		out.Groups = append(out.Groups, jg)
	}

	for _, person := range p.People {
		jp := jsonPerson{Name: person.Name, Kind: person.Kind}
		if person.Team != nil {
			jp.Team = person.Team.Name
		}

		if person.Group != nil {
			jp.Group = person.Group.Name
		}

		out.People = append(out.People, jp)
	}

	for _, c := range p.Clusters {
		jc := jsonCluster{Name: c.Name, Edition: c.Edition, Namespaces: []jsonNamespace{}}

		for _, ns := range c.Namespaces {
			out.Summary.Mounts += len(ns.Mounts)

			jn := jsonNamespace{Path: ns.Path}
			if depth >= 1 {
				for _, m := range ns.Mounts {
					jn.Mounts = append(jn.Mounts, mountJSON(m, depth))
				}
			}

			jc.Namespaces = append(jc.Namespaces, jn)
		}

		out.Clusters = append(out.Clusters, jc)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(out)
}

func orgJSON(n *Node) *jsonNode {
	if n == nil {
		return nil
	}

	jn := &jsonNode{Name: n.Name, Role: n.Role, Path: n.Path()}
	for _, a := range n.Apps {
		jn.Apps = append(jn.Apps, a.Name)
	}

	for _, c := range n.Children {
		jn.Children = append(jn.Children, orgJSON(c))
	}

	return jn
}

func mountJSON(m *Mount, depth int) jsonMount {
	jm := jsonMount{Path: m.Path, Model: m.Model, Apps: []string{}}
	for _, a := range m.Apps() {
		jm.Apps = append(jm.Apps, a.Name)
	}

	if depth < 3 {
		return jm
	}

	for _, sec := range m.Secrets {
		js := jsonSecret{
			Path: sec.Path(), App: sec.App.Name, Team: sec.App.Team.Name, Env: sec.Env,
			Thing: sec.Thing, Name: sec.Name, Segments: sec.Segments(), Grants: []jsonGrant{},
		}

		for _, g := range sec.Grants() {
			js.Grants = append(js.Grants, jsonGrant{Who: g.Who, Principal: g.Principal, Ops: g.Ops.String()})
		}

		jm.Secrets = append(jm.Secrets, js)
	}

	return jm
}
