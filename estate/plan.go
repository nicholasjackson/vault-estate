package estate

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
)

// App is something with its own Vault identity, owned by a team. It's a
// logical construct: in Vault it is only a folder, or a namespace.
type App struct {
	// Name is the app's name, unique within its team.
	Name string
	// Namespace is the app's own namespace, or cluster on community
	// edition, when its model gives it one: its name, or its team's and its
	// name when another app's namespace already has the name.
	Namespace string
	Team      *Node
	Model     string
	Platform  string
	Database  bool
	// KubeCluster is a Kubernetes app's cluster, i.e. k8s-original-2, and
	// AWSAccount a Lambda app's 12-digit AWS account ID.
	KubeCluster string
	AWSAccount  string
	// Group is the ops group that looks after the app.
	Group *OpsGroup
}

// Thing is a group of an app's secrets, i.e. db with a credential for each
// database role.
type Thing struct {
	Name    string
	Secrets []string
}

// Things returns the app's things, in each environment.
func (a *App) Things() []Thing {
	ts := []Thing{
		{Name: "config", Secrets: []string{"settings"}},
		{Name: "api", Secrets: []string{"key"}},
	}

	if a.Database {
		ts = append(ts, Thing{Name: "db", Secrets: []string{"read", "read-write", "admin"}})
	}

	return ts
}

// Segment is one folder of a secret's path, and what it is.
type Segment struct {
	Name string
	// Kind is folder (a manager's group in the org path), team, app, env or
	// thing.
	Kind string
}

// Secret is a KV secret: one of an app's secrets, in one environment, or in
// none when the model leaves the environment out.
type Secret struct {
	App   *App
	Env   string
	Thing string
	Name  string
	// Folders are the org folders, the part of the org path the namespace
	// doesn't capture.
	Folders []string
	// InApp is whether the app has a folder; it doesn't when it has a
	// namespace of its own.
	InApp bool
	// EnvFirst is whether the environment comes first, rather than after
	// the app.
	EnvFirst bool
}

// Segments returns the folders of the secret's path in its mount, in order.
func (s Secret) Segments() []Segment {
	var out []Segment
	if s.Env != "" && s.EnvFirst {
		out = append(out, Segment{s.Env, "env"})
	}

	// the org folders end with the app's team
	for i, f := range s.Folders {
		kind := "folder"
		if i == len(s.Folders)-1 {
			kind = "team"
		}

		out = append(out, Segment{f, kind})
	}

	if s.InApp {
		out = append(out, Segment{s.App.Name, "app"})
	}

	if s.Env != "" && !s.EnvFirst {
		out = append(out, Segment{s.Env, "env"})
	}

	return append(out, Segment{s.Thing, "thing"})
}

// Path is the secret's path in its mount.
func (s Secret) Path() string {
	var parts []string
	for _, seg := range s.Segments() {
		parts = append(parts, seg.Name)
	}

	return strings.Join(append(parts, s.Name), "/")
}

// Mount is a KV v2 mount and the secrets in it.
type Mount struct {
	Path    string
	Model   string
	Secrets []Secret
}

// Apps returns the apps with secrets in the mount, in order.
func (m *Mount) Apps() []*App {
	var as []*App
	for _, s := range m.Secrets {
		if !slices.Contains(as, s.App) {
			as = append(as, s.App)
		}
	}

	return as
}

// Namespace is a namespace and its mounts; the root namespace's Path is "".
type Namespace struct {
	Path   string
	Mounts []*Mount
}

// Cluster is a Vault cluster.
type Cluster struct {
	Name       string
	Edition    string
	Namespaces []*Namespace
}

// namespace returns the namespace at path, adding it and its parents when
// they don't exist yet.
func (c *Cluster) namespace(path string) *Namespace {
	for _, p := range append([]string{""}, ancestors(path)...) {
		if !slices.ContainsFunc(c.Namespaces, func(n *Namespace) bool { return n.Path == p }) {
			c.Namespaces = append(c.Namespaces, &Namespace{Path: p})
		}
	}

	for _, n := range c.Namespaces {
		if n.Path == path {
			return n
		}
	}

	return nil
}

// Plan is a customer's estate: its org, its apps and the clusters they use.
type Plan struct {
	Name         string
	Edition      string
	Industry     string
	Environments []string
	// Seed is the customer's seed, for anything else drawn from it.
	Seed int
	// Identity says whether the customer manages identity for people.
	Identity bool
	Org      *Node
	Apps     []*App
	Clusters []*Cluster
	Models   []ModelConfig
	// Groups are the ops groups, in org order; OpsManagers the ops managers
	// over them; and People everyone who logs in with a username and
	// password: by group, its manager and ops engineers, then each team's
	// developers, tester and PM, and the ops managers last.
	Groups      []*OpsGroup
	OpsManagers []*OpsManager
	People      []*Person
	// AWSAccounts are each model's made-up AWS account IDs, in order.
	AWSAccounts map[string][]string

	// taken are the app namespace names in use, by parent namespace
	taken map[string]bool
}

// Model returns the model called name.
func (p *Plan) Model(name string) ModelConfig {
	for _, m := range p.Models {
		if m.Name == name {
			return m
		}
	}

	return ModelConfig{}
}

// Secrets returns how many secrets the plan has.
func (p *Plan) Secrets() int {
	n := 0
	for _, c := range p.Clusters {
		for _, ns := range c.Namespaces {
			for _, m := range ns.Mounts {
				n += len(m.Secrets)
			}
		}
	}

	return n
}

// Depth is how many levels a team's org path has, i.e. 2 for em-1/checkout.
func (p *Plan) Depth() int {
	ts := p.Org.Teams()
	if len(ts) == 0 {
		return 0
	}

	return strings.Count(ts[0].Path(), "/") + 1
}

// Build lays out the estate the cluster block describes.
func Build(cfg Config) (*Plan, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("cluster %s: %w", cfg.Name(), err)
	}

	r := rand.New(rand.NewPCG(uint64(cfg.Seed), 0xe57a7e))

	total := 0
	for _, m := range cfg.Models {
		total += m.Apps
	}

	org, apps := buildOrg(r, total, Industries[cfg.Industry])

	p := &Plan{
		Name:         cfg.Name(),
		Edition:      cfg.Edition,
		Industry:     cfg.Industry,
		Environments: cfg.Environments,
		Seed:         cfg.Seed,
		Identity:     cfg.Identity,
		Org:          org,
		Apps:         apps,
		Models:       cfg.Models,
		Clusters:     []*Cluster{{Name: cfg.Name(), Edition: cfg.Edition}},
	}

	// the models take the apps in order, oldest first
	next := 0
	for _, m := range cfg.Models {
		mine := apps[next : next+m.Apps]
		next += m.Apps

		// validated above, so these can't fail
		platforms, _ := m.platformShares()
		databases, _ := m.databaseShare()

		assign(r, mine, platforms, databases)

		for _, a := range mine {
			a.Model = m.Name
			p.place(m, a)
		}
	}

	// people come from a stream of their own, so adding them moves nothing
	// above
	p.Groups, p.OpsManagers, p.People = buildPeople(rand.New(rand.NewPCG(uint64(cfg.Seed), 0x9e0b1e)), org)

	// and so does where apps run and which style each ops group writes
	placeApps(rand.New(rand.NewPCG(uint64(cfg.Seed), 0x5a1ace)), p)

	// the cluster block's own cluster first, then any clusters standing in
	// for namespaces on community edition
	extra := p.Clusters[1:]
	sort.SliceStable(extra, func(i, j int) bool { return extra[i].Name < extra[j].Name })

	for _, c := range p.Clusters {
		sort.SliceStable(c.Namespaces, func(i, j int) bool { return c.Namespaces[i].Path < c.Namespaces[j].Path })
	}

	return p, nil
}

// place lays out an app's secrets as its model says: in the namespace its
// model puts it in, in that namespace's secret/ mount, under the part of
// its org path the namespace doesn't capture.
func (p *Plan) place(m ModelConfig, a *App) {
	var (
		ns      string
		folders string
		inApp   = true
	)

	switch m.Namespace {
	case NamespaceNone:
		folders = a.Team.Path()
	case NamespacePerUnit:
		unit := a.Team.Unit()
		ns, folders = unit.Name, a.Team.PathFrom(unit)
	case NamespacePerApp:
		ns, inApp = p.appNamespace(a, ""), false
	case NamespacePerUnitPerApp:
		unit := a.Team.Unit().Name
		ns, inApp = unit+"/"+p.appNamespace(a, unit), false
	}

	// namespaces are enterprise only: on community edition each is a
	// cluster of its own
	c := p.Clusters[0]
	if ns != "" && p.Edition == EditionCommunity {
		c, ns = p.cluster(p.Name+"-"+strings.ReplaceAll(ns, "/", "-")), ""
	}

	mt := c.namespace(ns).mount("secret", m)

	var fs []string
	if folders != "" {
		fs = strings.Split(folders, "/")
	}

	envs := p.Environments
	if m.Env == EnvNone {
		envs = []string{""}
	}

	for _, env := range envs {
		for _, t := range a.Things() {
			for _, name := range t.Secrets {
				mt.Secrets = append(mt.Secrets, Secret{
					App: a, Env: env, Thing: t.Name, Name: name,
					Folders: fs, InApp: inApp, EnvFirst: m.Env == EnvFirst,
				})
			}
		}
	}
}

// appNamespace returns the name of the app's own namespace under parent:
// its own name, unless another app's namespace there has it already, when
// its team goes in front, as people do once there are two workers.
func (p *Plan) appNamespace(a *App, parent string) string {
	if p.taken == nil {
		p.taken = map[string]bool{}
	}

	name := a.Name
	if p.taken[parent+"/"+name] {
		name = a.Team.Name + "-" + a.Name
	}

	for i := 2; p.taken[parent+"/"+name]; i++ {
		name = fmt.Sprintf("%s-%s-%d", a.Team.Name, a.Name, i)
	}

	p.taken[parent+"/"+name] = true
	a.Namespace = name

	return name
}

// cluster returns the cluster called name, adding it when there is none.
func (p *Plan) cluster(name string) *Cluster {
	for _, c := range p.Clusters {
		if c.Name == name {
			return c
		}
	}

	c := &Cluster{Name: name, Edition: p.Edition}
	p.Clusters = append(p.Clusters, c)

	return c
}

// mount returns the model's mount called name, adding it when it doesn't
// exist yet. A name another model already uses in the namespace gets the
// model's name added, so each model's layout stays in a mount of its own.
func (n *Namespace) mount(name string, m ModelConfig) *Mount {
	for _, mt := range n.Mounts {
		if mt.Model == m.Name {
			return mt
		}
	}

	path := name
	if slices.ContainsFunc(n.Mounts, func(mt *Mount) bool { return mt.Path == name }) {
		path = name + "-" + m.Name
	}

	mt := &Mount{Path: path, Model: m.Name}
	n.Mounts = append(n.Mounts, mt)

	return mt
}

// assign gives the apps platforms in the shares given, and databases to the
// share given, both in hundredths of a percent, exactly rather than by
// chance, in a random order.
func assign(r *rand.Rand, apps []*App, platforms map[string]int, databases int) {
	names := make([]string, 0, len(platforms))
	for n := range platforms {
		names = append(names, n)
	}

	sort.Strings(names)

	var shares []int
	for _, n := range names {
		shares = append(shares, platforms[n])
	}

	var list []string
	for i, n := range apportion(len(apps), shares) {
		for range n {
			list = append(list, names[i])
		}
	}

	r.Shuffle(len(list), func(i, j int) { list[i], list[j] = list[j], list[i] })

	withDB := apportion(len(apps), []int{databases, 10000 - databases})[0]
	order := r.Perm(len(apps))

	for i, a := range apps {
		a.Platform = list[i]
		a.Database = order[i] < withDB
	}
}

// apportion splits n into parts in proportion to the shares, by largest
// remainder, so the parts always add up to n.
func apportion(n int, shares []int) []int {
	total := 0
	for _, s := range shares {
		total += s
	}

	parts := make([]int, len(shares))
	if total == 0 {
		return parts
	}

	type rem struct{ i, r int }

	var rems []rem
	given := 0
	for i, s := range shares {
		parts[i] = n * s / total
		given += parts[i]
		rems = append(rems, rem{i, n * s % total})
	}

	sort.SliceStable(rems, func(a, b int) bool { return rems[a].r > rems[b].r })

	for k := 0; given < n; k++ {
		parts[rems[k%len(rems)].i]++
		given++
	}

	return parts
}

// ancestors returns path and each of its parents, shortest first.
func ancestors(path string) []string {
	if path == "" {
		return nil
	}

	var out []string
	for i := range len(path) {
		if path[i] == '/' {
			out = append(out, path[:i])
		}
	}

	return append(out, path)
}
