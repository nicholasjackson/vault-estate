// Package manifest describes a simulated customer's whole Vault
// configuration as JSON: per cluster and namespace, the KV v2 mounts with
// their secrets and values, the auth mounts with their configuration, roles
// and users, the policies, and, when the customer manages identity, the
// entities, aliases and groups. Generate builds a manifest from an estate
// (estate); vaultapply applies one to Vault. A manifest is a pure
// function of the estate, so the same customer and seed always give the
// same bytes.
package manifest

import (
	"encoding/json"
	"io"
)

// Manifest is a customer's Vault configuration.
type Manifest struct {
	Customer string `json:"customer"`
	Edition  string `json:"edition"`
	Seed     int    `json:"seed"`
	Identity bool   `json:"identity"`
	// Org summarises the customer's ops groups, ops managers and people,
	// so the manifest can be checked without the estate.
	Org      Org       `json:"org"`
	Clusters []Cluster `json:"clusters"`
}

// Org is the customer's organisation, as far as Vault logins go.
type Org struct {
	Groups      []Group      `json:"groups"`
	OpsManagers []OpsManager `json:"ops_managers"`
	People      []Person     `json:"people"`
}

// Group is an ops group: up to four teams under one manager, with two ops
// engineers, sharing one policy style.
type Group struct {
	Name       string   `json:"name"`
	Manager    string   `json:"manager"`
	Ops        []string `json:"ops"`
	Teams      []string `json:"teams"`
	OpsManager string   `json:"ops_manager"`
	Model      string   `json:"model"`
	Style      string   `json:"style"`
}

// OpsManager is responsible for up to four ops groups.
type OpsManager struct {
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
}

// Person is someone who logs in with a username and password.
type Person struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Team  string `json:"team,omitempty"`
	Group string `json:"group,omitempty"`
}

// Cluster is one Vault cluster and its namespaces, root first.
type Cluster struct {
	Name       string      `json:"name"`
	Namespaces []Namespace `json:"namespaces"`
}

// Namespace is what lives in one namespace; the root's Path is "".
type Namespace struct {
	Path         string          `json:"path"`
	SecretMounts []SecretMount   `json:"secret_mounts,omitempty"`
	AuthMounts   []AuthMount     `json:"auth_mounts,omitempty"`
	Policies     []Policy        `json:"policies,omitempty"`
	Entities     []Entity        `json:"entities,omitempty"`
	Groups       []IdentityGroup `json:"groups,omitempty"`
}

// SecretMount is a KV v2 mount and its secrets.
type SecretMount struct {
	Path    string   `json:"path"`
	Secrets []Secret `json:"secrets"`
}

// Secret is one KV v2 secret: where it sits in its mount, whose it is, and
// its made-up values.
type Secret struct {
	Path string `json:"path"`
	// App is the owning app's id, <team>-<app>.
	App   string            `json:"app"`
	Team  string            `json:"team"`
	Env   string            `json:"env,omitempty"`
	Thing string            `json:"thing"`
	Name  string            `json:"name"`
	Data  map[string]string `json:"data"`
}

// AuthMount is an auth method's mount: its configuration and its roles or
// users.
type AuthMount struct {
	Path string `json:"path"`
	// Type is kubernetes, approle, aws or userpass.
	Type   string        `json:"type"`
	Config []ConfigWrite `json:"config,omitempty"`
	Roles  []Role        `json:"roles,omitempty"`
	Users  []User        `json:"users,omitempty"`
}

// ConfigWrite is one write of an auth mount's configuration, at a path
// relative to auth/<mount>/, i.e. config or config/sts/<account>.
type ConfigWrite struct {
	Path string         `json:"path"`
	Data map[string]any `json:"data"`
}

// Role is a machine login: a Kubernetes, AppRole or AWS IAM role.
type Role struct {
	Name string `json:"name"`
	// Apps are the ids of the apps that log in with the role; more than one
	// for an ops group's shared legacy AppRole.
	Apps     []string       `json:"apps"`
	Config   map[string]any `json:"config,omitempty"`
	Policies []string       `json:"policies,omitempty"`
	// SecretIDMetadata is set on the SecretID apply creates for an AppRole
	// role whose policy is templated from it.
	SecretIDMetadata map[string]string `json:"secret_id_metadata,omitempty"`
}

// User is a person's username and password login.
type User struct {
	Name     string   `json:"name"`
	Password string   `json:"password"`
	Person   string   `json:"person"`
	Policies []string `json:"policies,omitempty"`
}

// Policy is an ACL policy: its rules as data, and the HCL rendered from
// them.
type Policy struct {
	Name string `json:"name"`
	// Style is per-app, templated or legacy.
	Style string `json:"style"`
	// Group is the ops group the policy belongs to.
	Group string `json:"group"`
	Rules []Rule `json:"rules"`
	// Text is the HCL rendered from Rules. It may name an auth mount by
	// ${accessor:<mount path>}, which apply replaces with the mount's
	// accessor in the policy's own cluster and namespace.
	Text string `json:"text"`
	// Quirks mark deliberate mess: orphan, dead-rule, near-duplicate, sudo,
	// deny, wildcard or env-wide.
	Quirks []string `json:"quirks,omitempty"`
}

// Rule grants capabilities on a path.
type Rule struct {
	Path         string   `json:"path"`
	Capabilities []string `json:"capabilities"`
}

// Entity is an identity entity and its aliases.
type Entity struct {
	Name     string            `json:"name"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Aliases  []Alias           `json:"aliases,omitempty"`
}

// Alias ties an entity to a login on an auth mount, named by its path in
// the entity's namespace.
type Alias struct {
	Name           string            `json:"name"`
	Mount          string            `json:"mount"`
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
}

// IdentityGroup is an internal group: its members and the policies they
// get through it.
type IdentityGroup struct {
	Name     string      `json:"name"`
	Policies []string    `json:"policies,omitempty"`
	Members  []MemberRef `json:"members,omitempty"`
}

// MemberRef names an entity in the group's namespace or one above it.
type MemberRef struct {
	Namespace string `json:"namespace"`
	Entity    string `json:"entity"`
}

// Write writes the manifest as indented JSON, with a trailing newline.
func Write(w io.Writer, m *Manifest) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	return enc.Encode(m)
}

// Read reads a manifest written by Write.
func Read(r io.Reader) (*Manifest, error) {
	var m Manifest
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return nil, err
	}

	return &m, nil
}
