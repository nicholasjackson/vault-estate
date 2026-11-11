package estate

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// Levels are how deep Render goes, shallowest first.
var Levels = []string{"namespace", "mount", "app", "secret"}

// RenderOptions says how to render a plan.
type RenderOptions struct {
	// Level is how deep to go: namespace, mount, app or secret (the
	// default).
	Level string
	// Plain turns colour off; without it colour is used when w is a
	// terminal.
	Plain bool
}

// levelDepth returns the level's index in Levels; "" is secret, the deepest.
func levelDepth(level string) (int, error) {
	if level == "" {
		level = "secret"
	}

	for i, l := range Levels {
		if l == level {
			return i, nil
		}
	}

	return -1, fmt.Errorf("unknown level %q, use one of %v", level, Levels)
}

// glyphs tell the kinds of node apart, with or without colour; each is a
// single code point, so terminals give them the same width
const (
	glyphCluster   = "🏢"
	glyphNamespace = "📦"
	glyphMount     = "💾"
	glyphFolder    = "📁"
	glyphTeam      = "👥"
	glyphApp       = "🧩"
	glyphSecret    = "🔑"
)

type styles struct {
	cluster, namespace, mount, team, app, secret, faint lipgloss.Style
}

func newStyles(w io.Writer, plain bool) styles {
	r := lipgloss.NewRenderer(w)
	if plain {
		r.SetColorProfile(termenv.Ascii)
	}

	return styles{
		cluster:   r.NewStyle().Bold(true),
		namespace: r.NewStyle().Foreground(lipgloss.Color("5")).Bold(true),
		mount:     r.NewStyle().Foreground(lipgloss.Color("6")).Bold(true),
		team:      r.NewStyle().Foreground(lipgloss.Color("4")),
		app:       r.NewStyle().Foreground(lipgloss.Color("3")),
		secret:    r.NewStyle().Foreground(lipgloss.Color("2")),
		faint:     r.NewStyle().Faint(true),
	}
}

// tree is a node to print, with its children in the order added.
type tree struct {
	label    string
	children []*tree
	byKey    map[string]*tree
}

func (t *tree) add(label string) *tree {
	c := &tree{label: label}
	t.children = append(t.children, c)

	return c
}

// child returns the child with key, adding it with label when there is none.
func (t *tree) child(key, label string) *tree {
	if t.byKey == nil {
		t.byKey = map[string]*tree{}
	}

	if c, ok := t.byKey[key]; ok {
		return c
	}

	c := t.add(label)
	t.byKey[key] = c

	return c
}

func (t *tree) print(w io.Writer, prefix string) {
	for i, c := range t.children {
		branch, indent := "├── ", "│   "
		if i == len(t.children)-1 {
			branch, indent = "└── ", "    "
		}

		fmt.Fprintln(w, prefix+branch+c.label)
		c.print(w, prefix+indent)
	}
}

// Render writes the plan to w as a tree: each cluster, its namespaces, its
// mounts, the folders and apps in them, and the secrets.
func Render(w io.Writer, p *Plan, o RenderOptions) error {
	depth, err := levelDepth(o.Level)
	if err != nil {
		return err
	}

	s := newStyles(w, o.Plain)

	mounts := 0
	for _, c := range p.Clusters {
		for _, ns := range c.Namespaces {
			mounts += len(ns.Mounts)
		}
	}

	fmt.Fprintf(w, "%s  %s\n", s.cluster.Render(p.Name), s.faint.Render(fmt.Sprintf(
		"%s · %s · %s · %s · org depth %d · %s · %s · %s",
		p.Edition, p.Industry, count(len(p.Apps), "app"), count(len(p.Org.Teams()), "team"), p.Depth(),
		count(len(p.Clusters), "cluster"), count(mounts, "mount"), count(p.Secrets(), "secret"))))

	var models []string
	for _, m := range p.Models {
		models = append(models, fmt.Sprintf("%s (%s, namespace %s, env %s)", m.Name, count(m.Apps, "app"), m.Namespace, m.Env))
	}

	fmt.Fprintln(w, s.faint.Render("models: "+strings.Join(models, " · ")))
	fmt.Fprintln(w, s.faint.Render(fmt.Sprintf("people: %d, in %s under %s",
		len(p.People), count(len(p.Groups), "ops group"), count(len(p.OpsManagers), "ops manager"))))
	fmt.Fprintf(w, "%s\n\n", s.faint.Render(fmt.Sprintf("%s cluster  %s namespace  %s mount  %s folder  %s team  %s app (and its platform)  %s secret",
		glyphCluster, glyphNamespace, glyphMount, glyphFolder, glyphTeam, glyphApp, glyphSecret)))

	for i, c := range p.Clusters {
		if i > 0 {
			fmt.Fprintln(w)
		}

		root := &tree{}
		fmt.Fprintf(w, "%s %s %s\n", s.cluster.Render(glyphCluster), s.cluster.Render("cluster "+c.Name), s.faint.Render(c.Edition))

		// a community cluster has no namespaces, so its mounts hang off the
		// cluster; an enterprise cluster's start at the root namespace
		parents := map[string]*tree{}
		for _, ns := range c.Namespaces {
			parent := root
			if ns.Path != "" {
				parent = parents[parentNamespace(ns.Path)]
			}

			node := parent
			if c.Edition == EditionEnterprise {
				name := "root"
				if ns.Path != "" {
					name = ns.Path[strings.LastIndex(ns.Path, "/")+1:] + "/"
				}

				node = parent.add(s.namespace.Render(glyphNamespace+" "+name) + s.faint.Render(namespaceNote(ns)))
			}

			parents[ns.Path] = node

			if depth < 1 {
				continue
			}

			for _, m := range ns.Mounts {
				renderMount(node, m, depth, s)
			}
		}

		root.print(w, "")
	}

	return nil
}

func renderMount(parent *tree, m *Mount, depth int, s styles) {
	apps := m.Apps()

	note := fmt.Sprintf("  %s · %s · %s", m.Model, count(len(apps), "app"), count(len(m.Secrets), "secret"))

	// an app with a namespace of its own has no folder: say whose it is here
	appless := len(m.Secrets) > 0 && !m.Secrets[0].InApp
	if appless && len(apps) == 1 {
		note = fmt.Sprintf("  %s · %s · %s", m.Model, s.app.Render(glyphApp+" "+apps[0].Name)+s.faint.Render(" of "+apps[0].Team.Name+" on "+platformNote(apps[0])), count(len(m.Secrets), "secret"))
	}

	mt := parent.add(s.mount.Render(glyphMount+" "+m.Path+"/") + s.faint.Render(note))

	if depth < 2 || (appless && depth < 3) {
		return
	}

	// at app level, each app node says how many secrets are under it, which
	// for an environment-first layout is that environment's share
	counts := map[string]int{}
	for _, sec := range m.Secrets {
		key := ""
		for _, seg := range sec.Segments() {
			key += seg.Name + "/"
			if seg.Kind == "app" {
				counts[key]++
				break
			}
		}
	}

	for _, sec := range m.Secrets {
		node, key := mt, ""

		for _, seg := range sec.Segments() {
			// at app level, stop at the app
			if depth < 3 && seg.Kind != "app" && !hasAppAfter(sec, seg) {
				break
			}

			key += seg.Name + "/"

			label := glyphFolder + " " + seg.Name + "/"
			if seg.Kind == "team" {
				label = s.team.Render(glyphTeam + " " + seg.Name + "/")
			}

			if seg.Kind == "app" {
				label = s.app.Render(glyphApp+" "+seg.Name+"/") + s.faint.Render("  "+platformNote(sec.App))
				if depth < 3 {
					label += s.faint.Render(" · " + count(counts[key], "secret"))
				}
			}

			node = node.child(key, label)

			if seg.Kind == "app" && depth < 3 {
				break
			}
		}

		if depth >= 3 {
			node.add(s.secret.Render(glyphSecret+" "+sec.Name) + s.faint.Render("  "+grantNote(sec)))
		}
	}
}

// hasAppAfter reports whether the secret's app folder comes after seg, so
// seg is above the app.
func hasAppAfter(sec Secret, seg Segment) bool {
	if !sec.InApp {
		return false
	}

	for _, x := range sec.Segments() {
		if x == seg {
			return true
		}

		if x.Kind == "app" {
			return false
		}
	}

	return false
}

// grantNote lists who may use the secret, i.e. app r · developers rw.
func grantNote(sec Secret) string {
	var parts []string
	for _, g := range sec.Grants() {
		parts = append(parts, string(g.Who)+" "+g.Ops.String())
	}

	return strings.Join(parts, " · ")
}

func platformNote(a *App) string {
	if a.Database {
		return a.Platform + " · db"
	}

	return a.Platform
}

func namespaceNote(ns *Namespace) string {
	if len(ns.Mounts) == 0 {
		return ""
	}

	return "  " + count(len(ns.Mounts), "mount")
}

// count returns n and the noun, plural unless n is 1.
func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}

	return fmt.Sprintf("%d %ss", n, noun)
}

func parentNamespace(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[:i]
	}

	return ""
}
