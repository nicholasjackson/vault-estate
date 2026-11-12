// Command vault-estate lays out simulated customer Vault estates, described
// in xcl (see the examples folder), prints them as a tree or
// as JSON, generates a manifest of each customer's Vault configuration, and
// applies a manifest to empty Vault clusters. See packages estate, manifest
// and vaultapply.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/nicholasjackson/vault-estate/estate"
	"github.com/nicholasjackson/vault-estate/manifest"
	"github.com/nicholasjackson/vault-estate/vaultapply"
)

// version is set at build time with -ldflags "-X main.version=<version>".
var version = "dev"

var commands = map[string]func(ctx context.Context, args []string) error{
	"show":     show,
	"generate": generate,
	"apply":    apply,
	"version":  printVersion,
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage(os.Stderr)
		os.Exit(2)
	}

	cmd, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cmd(ctx, os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}

		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: vault-estate <command> [flags]

Commands:
  show      <xcl> lay out a customer and print its clusters, namespaces,
            mounts and secrets as a tree, or as JSON with -json
  generate  <xcl> write a manifest of a customer's whole Vault configuration
            as JSON
  apply     apply a manifest to empty Vault clusters, one address per cluster
  version   print the version

<xcl> is a file or folder of customer cluster blocks, such as
examples/noths.xcl.

Run "vault-estate <command> -h" for a command's flags.
`)
}

func show(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.Usage = commandUsage(fs, "show <xcl file or folder> [flags]")
	name := fs.String("name", "", "the cluster block to show; required when there is more than one")
	level := fs.String("level", "secret", "how deep to show: "+strings.Join(estate.Levels, ", "))
	plain := fs.Bool("plain", false, "no colour")
	asJSON := fs.Bool("json", false, "print the estate as JSON rather than a tree")

	path, err := parsePath(fs, args)
	if err != nil {
		return err
	}

	cfg, err := loadCustomer(path, *name)
	if err != nil {
		return err
	}

	p, err := estate.Build(cfg)
	if err != nil {
		return err
	}

	o := estate.RenderOptions{Level: *level, Plain: *plain}
	if *asJSON {
		return estate.RenderJSON(os.Stdout, p, o)
	}

	return estate.Render(os.Stdout, p, o)
}

func generate(_ context.Context, args []string) (err error) {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.Usage = commandUsage(fs, "generate <xcl file or folder> [flags]")
	name := fs.String("name", "", "the cluster block to generate; required when there is more than one")
	out := fs.String("out", "-", "file to write the manifest to; - for standard output")

	path, err := parsePath(fs, args)
	if err != nil {
		return err
	}

	cfg, err := loadCustomer(path, *name)
	if err != nil {
		return err
	}

	p, err := estate.Build(cfg)
	if err != nil {
		return err
	}

	m, err := manifest.Generate(p)
	if err != nil {
		return err
	}

	if *out == "-" {
		return manifest.Write(os.Stdout, m)
	}

	f, err := os.Create(*out)
	if err != nil {
		return err
	}

	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()

	return manifest.Write(f, m)
}

// parsePath parses a command's flags and returns its one argument, the xcl
// file or folder. Flags may come before or after it.
func parsePath(fs *flag.FlagSet, args []string) (string, error) {
	var paths []string
	for {
		if err := fs.Parse(args); err != nil {
			return "", err
		}

		if fs.NArg() == 0 {
			break
		}

		paths = append(paths, fs.Arg(0))
		args = fs.Args()[1:]
	}

	switch len(paths) {
	case 0:
		return "", fmt.Errorf("give the customer's xcl file or folder, such as: vault-estate %s examples/noths.xcl", fs.Name())
	case 1:
		return paths[0], nil
	default:
		return "", fmt.Errorf("give one xcl file or folder, not %d: %s", len(paths), strings.Join(paths, " "))
	}
}

// commandUsage prints a command's usage line and its flags.
func commandUsage(fs *flag.FlagSet, line string) func() {
	return func() {
		fmt.Fprintf(fs.Output(), "Usage: vault-estate %s\n\nFlags:\n", line)
		fs.PrintDefaults()
	}
}

// loadCustomer returns the cluster block called name from the xcl file or
// folder at path, or its only block when name is empty.
func loadCustomer(path, name string) (estate.Config, error) {
	from := path

	cfgs, err := estate.Load(path)
	if err != nil {
		return estate.Config{}, err
	}

	var names []string
	for _, c := range cfgs {
		names = append(names, c.Name())
	}

	if name == "" && len(cfgs) == 1 {
		name = names[0]
	}

	for _, c := range cfgs {
		if c.Name() == name {
			return c, nil
		}
	}

	if name == "" {
		return estate.Config{}, fmt.Errorf("%s has %d customers, pick one with -name: %s", from, len(names), strings.Join(names, ", "))
	}

	return estate.Config{}, fmt.Errorf("no customer %q in %s, use -name with one of: %s", name, from, strings.Join(names, ", "))
}

func printVersion(_ context.Context, _ []string) error {
	fmt.Println(version)
	return nil
}

func apply(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	file := fs.String("manifest", "", "the manifest to apply, from vault-estate generate; - for standard input")
	addrs := addrFlag{}
	fs.Var(addrs, "addr", "a cluster's Vault address, as <cluster>=<url>; one for every cluster in the manifest, or $VAULT_ADDR for a manifest of one cluster")
	token := fs.String("token", os.Getenv("VAULT_TOKEN"), "the token for every cluster; $VAULT_TOKEN by default")
	workers := fs.Int("workers", 8, "how many secrets to write at once")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *file == "" {
		return errors.New("give the manifest to apply with -manifest")
	}

	in := io.Reader(os.Stdin)
	if *file != "-" {
		f, err := os.Open(*file)
		if err != nil {
			return err
		}
		defer f.Close()

		in = f
	}

	m, err := manifest.Read(in)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *file, err)
	}

	if err := addrFromEnv(addrs, m, os.Getenv("VAULT_ADDR")); err != nil {
		return err
	}

	if err := vaultapply.Apply(ctx, m, vaultapply.Options{Addrs: addrs, Token: *token, Workers: *workers}); err != nil {
		return err
	}

	for _, c := range m.Clusters {
		var mounts, policies, users, secrets int
		for _, ns := range c.Namespaces {
			mounts += len(ns.SecretMounts) + len(ns.AuthMounts)
			policies += len(ns.Policies)

			for _, am := range ns.AuthMounts {
				users += len(am.Users)
			}

			for _, sm := range ns.SecretMounts {
				secrets += len(sm.Secrets)
			}
		}

		fmt.Printf("%s: %d namespaces, %d mounts, %d policies, %d users, %d secrets\n",
			c.Name, len(c.Namespaces), mounts, policies, users, secrets)
	}

	return nil
}

// addrFromEnv addresses the manifest's only cluster at env, $VAULT_ADDR,
// when no -addr is given. One address can't stand for more than one cluster.
func addrFromEnv(addrs addrFlag, m *manifest.Manifest, env string) error {
	if len(addrs) > 0 || env == "" {
		return nil
	}

	if len(m.Clusters) != 1 {
		var names []string
		for _, c := range m.Clusters {
			names = append(names, c.Name)
		}

		return fmt.Errorf("$VAULT_ADDR is one address, but the manifest has %d clusters: give each with -addr <cluster>=<url>: %s",
			len(m.Clusters), strings.Join(names, ", "))
	}

	addrs[m.Clusters[0].Name] = env

	return nil
}

// addrFlag collects -addr <cluster>=<url> flags.
type addrFlag map[string]string

func (a addrFlag) String() string {
	var parts []string
	for name, url := range a {
		parts = append(parts, name+"="+url)
	}

	return strings.Join(parts, ",")
}

func (a addrFlag) Set(v string) error {
	name, url, ok := strings.Cut(v, "=")
	if !ok || name == "" || url == "" {
		return fmt.Errorf("%q isn't <cluster>=<url>", v)
	}

	if _, dup := a[name]; dup {
		return fmt.Errorf("cluster %s is given more than once", name)
	}

	a[name] = url

	return nil
}
