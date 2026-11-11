// Package estate generates a simulated customer's Vault estate from a short
// description: how many apps each model serves, and where they run. From the
// app count it works out an org (teams, and the managers above them), places
// each model on the part of the org its app count fills, and lays out the
// clusters, namespaces, mounts and secrets that result. See
// customers/noths.xcl for the template.
package estate

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/jumppad-labs/xcl"
	"github.com/jumppad-labs/xcl/registry"
	"github.com/jumppad-labs/xcl/types"
)

// Config is a cluster block: one customer's cluster, sized by the apps its
// models serve.
type Config struct {
	Edition      string   `xcl:"edition,optional"`
	Industry     string   `xcl:"industry,optional"`
	Environments []string `xcl:"environments,optional"`
	Seed         int      `xcl:"seed,optional"`
	// Identity says whether the customer manages identity for people:
	// entities, aliases and groups, with people's policies coming through
	// the groups. Off by default.
	Identity bool          `xcl:"identity,optional"`
	Models   []ModelConfig `xcl:"model,block"`

	// Meta is filled by xcl; its Name is the cluster's name.
	Meta types.Meta `json:"-"`
}

// ModelConfig is a model block: how many apps are laid out one way. Where
// its namespaces sit, and where the environment goes in the path, decide
// everything else: the part of the org path a namespace doesn't capture
// becomes folders, then the app (unless it has a namespace of its own), then
// the thing and the secret.
type ModelConfig struct {
	Name      string `xcl:"name,label"`
	Apps      int    `xcl:"apps"`
	Namespace string `xcl:"namespace,optional"`
	Env       string `xcl:"env,optional"`
	// Platforms are where the model's apps run, as percentages adding up
	// to 100%, i.e. { kubernetes = "70%", vm = "30%" }; every model says.
	Platforms map[string]string `xcl:"platforms"`
	// Databases is the percentage of the model's apps that own a database,
	// i.e. "50%".
	Databases string `xcl:"databases,optional"`
	// KubernetesClusters is how many Kubernetes clusters the model's
	// Kubernetes apps are spread over; 1 by default. A pointer, so a 0 that
	// is written can be told from one that isn't.
	KubernetesClusters *int `xcl:"kubernetes_clusters,optional"`
	// AWSAccounts is how many AWS accounts the model's Lambda apps are
	// spread over; 1 by default.
	AWSAccounts *int `xcl:"aws_accounts,optional"`
	// AWSMounts is how the Lambda apps log in: through one shared AWS auth
	// mount, or one mount per account; shared by default.
	AWSMounts string `xcl:"aws_mounts,optional"`
	// Policies is the share of the model's ops groups using each policy
	// style, as percentages adding up to 100%, i.e.
	// { per-app = "60%", templated = "30%", legacy = "10%" }; all per-app by
	// default.
	Policies map[string]string `xcl:"policies,optional"`
	// UserAuth is where people log in on enterprise: at the root, or in the
	// unit's namespace. By default the root for models with no namespaces
	// or a namespace per app, and the unit for models with a namespace per
	// unit.
	UserAuth string `xcl:"user_auth,optional"`
}

// policyShares returns the model's policy styles' shares in hundredths of a
// percent, adding up to 10000; all per-app when the model sets no mix.
func (m ModelConfig) policyShares() (map[string]int, error) {
	if len(m.Policies) == 0 {
		return map[string]int{StylePerApp: 10000}, nil
	}

	out := map[string]int{}
	total := 0
	for name, v := range m.Policies {
		if !slices.Contains(Styles, name) {
			return nil, fmt.Errorf("unknown policy style %q, use one of %v", name, Styles)
		}

		share, err := parsePercent(v)
		if err != nil {
			return nil, fmt.Errorf("policy style %s: %w", name, err)
		}

		out[name] = share
		total += share
	}

	if total != 10000 {
		return nil, fmt.Errorf("policies add up to %s, not 100%%", formatPercent(total))
	}

	return out, nil
}

// platformShares returns the model's platforms' shares in hundredths of a
// percent, so they add up to 10000.
func (m ModelConfig) platformShares() (map[string]int, error) {
	if len(m.Platforms) == 0 {
		return nil, fmt.Errorf("platforms: say where the model's apps run, as percentages adding up to 100%%")
	}

	out := map[string]int{}
	total := 0
	for name, v := range m.Platforms {
		share, err := parsePercent(v)
		if err != nil {
			return nil, fmt.Errorf("platform %s: %w", name, err)
		}

		out[name] = share
		total += share
	}

	if total != 10000 {
		return nil, fmt.Errorf("platforms add up to %s, not 100%%", formatPercent(total))
	}

	return out, nil
}

// databaseShare returns the share of the model's apps that own a database,
// in hundredths of a percent; none when it isn't given.
func (m ModelConfig) databaseShare() (int, error) {
	if m.Databases == "" {
		return 0, nil
	}

	share, err := parsePercent(m.Databases)
	if err != nil {
		return 0, fmt.Errorf("databases: %w", err)
	}

	return share, nil
}

// parsePercent reads a percentage from 0% to 100%, i.e. "50%" or "12.5%",
// in hundredths of a percent.
func parsePercent(v string) (int, error) {
	num, ok := strings.CutSuffix(strings.TrimSpace(v), "%")
	if !ok {
		return 0, fmt.Errorf("%q is not a percentage; write it as, say, \"50%%\"", v)
	}

	f, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
	if err != nil || f < 0 || f > 100 {
		return 0, fmt.Errorf("%q is not a percentage from 0%% to 100%%", v)
	}

	return int(math.Round(f * 100)), nil
}

func formatPercent(hundredths int) string {
	return strconv.FormatFloat(float64(hundredths)/100, 'f', -1, 64) + "%"
}

// Name is the cluster's name.
func (c Config) Name() string {
	return c.Meta.Name
}

const (
	EditionCommunity  = "community"
	EditionEnterprise = "enterprise"

	// NamespaceNone keeps everything in the root namespace, with the org
	// path as folders.
	NamespaceNone = "none"
	// NamespacePerUnit gives each unit, the layer under the CTO, a
	// namespace.
	NamespacePerUnit = "per-unit"
	// NamespacePerApp gives each app a namespace of its own.
	NamespacePerApp = "per-app"
	// NamespacePerUnitPerApp nests a namespace per app in a namespace per
	// unit.
	NamespacePerUnitPerApp = "per-unit/per-app"

	// EnvNone leaves the environment out: one set of secrets, as when each
	// environment has its own cluster, or the same secrets are used
	// everywhere.
	EnvNone = "none"
	// EnvFirst puts the environment first in the path.
	EnvFirst = "first"
	// EnvAfterApp puts the environment after the app.
	EnvAfterApp = "after-app"

	// AWSMountsShared logs every Lambda app in through one AWS auth mount
	// configured for all the model's accounts.
	AWSMountsShared = "shared"
	// AWSMountsPerAccount gives each AWS account its own auth mount.
	AWSMountsPerAccount = "per-account"

	// StylePerApp is the tidy style: a policy per app and environment, per
	// team role and per ops group, granting exactly the estate's paths.
	StylePerApp = "per-app"
	// StyleTemplated fills in one policy per auth mount from the login's
	// identity.
	StyleTemplated = "templated"
	// StyleLegacy reproduces the mess real estates accumulate.
	StyleLegacy = "legacy"

	// UserAuthRoot puts people's logins in the root namespace.
	UserAuthRoot = "root"
	// UserAuthUnit puts people's logins in their unit's namespace.
	UserAuthUnit = "unit"
)

// Namespaces are the namespace placements, Envs the environment placements,
// AWSMountArrangements the ways Lambda apps log in, Styles the policy styles
// and UserAuths where people can log in.
var (
	Namespaces           = []string{NamespaceNone, NamespacePerUnit, NamespacePerApp, NamespacePerUnitPerApp}
	Envs                 = []string{EnvNone, EnvFirst, EnvAfterApp}
	AWSMountArrangements = []string{AWSMountsShared, AWSMountsPerAccount}
	Styles               = []string{StylePerApp, StyleTemplated, StyleLegacy}
	UserAuths            = []string{UserAuthRoot, UserAuthUnit}
)

func ptr[T any](v T) *T {
	return &v
}

// hasUnitNamespace says whether a namespace placement gives each unit a
// namespace.
func hasUnitNamespace(namespace string) bool {
	return namespace == NamespacePerUnit || namespace == NamespacePerUnitPerApp
}

type configs struct {
	Clusters []*Config
}

// Load reads the cluster blocks in the xcl files, or the .xcl files in the
// folders, at paths.
func Load(paths ...string) ([]Config, error) {
	r := registry.NewLocal()
	r.RegisterType(&Config{}, "cluster")

	c, err := xcl.NewConfig(xcl.WithRegistry(r))
	if err != nil {
		return nil, err
	}

	if err := c.Apply(paths...); err != nil {
		return nil, err
	}

	var cs configs
	if err := c.Decode(&cs); err != nil {
		return nil, err
	}

	var out []Config
	for _, cfg := range cs.Clusters {
		out = append(out, *cfg)
	}

	return out, nil
}

func (c Config) withDefaults() Config {
	if c.Edition == "" {
		c.Edition = EditionCommunity
	}

	if c.Industry == "" {
		c.Industry = "saas"
	}

	if len(c.Environments) == 0 {
		c.Environments = []string{"dev", "staging", "prod"}
	}

	if c.Seed == 0 {
		c.Seed = 1
	}

	c.Models = slices.Clone(c.Models)
	for i, m := range c.Models {
		if m.Namespace == "" {
			c.Models[i].Namespace = NamespaceNone
		}

		if m.Env == "" {
			c.Models[i].Env = EnvAfterApp
		}

		if m.KubernetesClusters == nil {
			c.Models[i].KubernetesClusters = ptr(1)
		}

		if m.AWSAccounts == nil {
			c.Models[i].AWSAccounts = ptr(1)
		}

		if m.AWSMounts == "" {
			c.Models[i].AWSMounts = AWSMountsShared
		}

		// people log in at the highest namespace above their secrets: the
		// unit's when the model has one, the root otherwise
		if m.UserAuth == "" {
			c.Models[i].UserAuth = UserAuthRoot
			if hasUnitNamespace(c.Models[i].Namespace) {
				c.Models[i].UserAuth = UserAuthUnit
			}
		}
	}

	return c
}

func (c Config) validate() error {
	switch c.Edition {
	case EditionCommunity, EditionEnterprise:
	default:
		return fmt.Errorf("unknown edition %q, use community or enterprise", c.Edition)
	}

	if _, ok := Industries[c.Industry]; !ok {
		return fmt.Errorf("unknown industry %q, use one of %v", c.Industry, IndustryNames())
	}

	if len(c.Models) == 0 {
		return fmt.Errorf("no models: a cluster needs at least one model block")
	}

	names := map[string]bool{}
	for _, m := range c.Models {
		if names[m.Name] {
			return fmt.Errorf("model %q is given more than once", m.Name)
		}

		names[m.Name] = true

		if !slices.Contains(Namespaces, m.Namespace) {
			return fmt.Errorf("model %s: unknown namespace %q, use one of %v", m.Name, m.Namespace, Namespaces)
		}

		if !slices.Contains(Envs, m.Env) {
			return fmt.Errorf("model %s: unknown env %q, use one of %v", m.Name, m.Env, Envs)
		}

		if m.Apps < 1 {
			return fmt.Errorf("model %s: apps must be at least 1", m.Name)
		}

		if _, err := m.databaseShare(); err != nil {
			return fmt.Errorf("model %s: %w", m.Name, err)
		}

		if _, err := m.platformShares(); err != nil {
			return fmt.Errorf("model %s: %w", m.Name, err)
		}

		if *m.KubernetesClusters < 1 {
			return fmt.Errorf("model %s: kubernetes_clusters must be at least 1", m.Name)
		}

		if *m.AWSAccounts < 1 {
			return fmt.Errorf("model %s: aws_accounts must be at least 1", m.Name)
		}

		if !slices.Contains(AWSMountArrangements, m.AWSMounts) {
			return fmt.Errorf("model %s: unknown aws_mounts %q, use one of %v", m.Name, m.AWSMounts, AWSMountArrangements)
		}

		if _, err := m.policyShares(); err != nil {
			return fmt.Errorf("model %s: %w", m.Name, err)
		}

		if !slices.Contains(UserAuths, m.UserAuth) {
			return fmt.Errorf("model %s: unknown user_auth %q, use one of %v", m.Name, m.UserAuth, UserAuths)
		}

		if m.UserAuth == UserAuthUnit && !hasUnitNamespace(m.Namespace) {
			return fmt.Errorf("model %s: user_auth %q needs a namespace per unit (namespace %s or %s)", m.Name, m.UserAuth, NamespacePerUnit, NamespacePerUnitPerApp)
		}
	}

	return nil
}
