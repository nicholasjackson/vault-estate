# vault-estate

`vault-estate` lays out random but realistic Vault estates, from a short
description of each customer (`estate`), turns each into a manifest of its
whole Vault configuration (`manifest`), and applies a manifest to empty Vault
clusters (`vaultapply`). Use it to stand up a Vault that looks like a real
customer's, to test migrations, tooling and policy analysis against.

## Install

Download a binary from the
[releases](https://github.com/nicholasjackson/vault-estate/releases), or:

```bash
go install github.com/nicholasjackson/vault-estate@latest
```

Or run the container image, `ghcr.io/nicholasjackson/vault-estate` (see
[Using the container](#using-the-container)).

```bash
vault-estate show examples/noths.xcl                       # the whole estate, as a tree
vault-estate generate examples/noths.xcl -out noths.json   # its Vault configuration, as a manifest
vault-estate apply -manifest noths.json -addr noths=http://127.0.0.1:8200 -token root
```

## Customers

Customers are `cluster` blocks in xcl. `show` and `generate` take an xcl file,
or a folder of them; when it holds more than one customer, pick one with
`-name`. There are five examples in `examples/`: `startup`, `noths`, `scaleup`,
`bank` and `retail-group`.

A cluster block gives the edition, the industry (which names the teams and
apps), the environments and a seed; each `model` block is a set of apps laid
out the same way. A customer with history has more than one model, oldest first:

```hcl
cluster "startup" {
  edition      = "community"
  industry     = "saas"
  environments = ["dev", "prod"]
  seed         = 1
  identity     = false             # people get entities and groups

  model "everything" {
    apps      = 9
    namespace = "none"             # none | per-unit | per-app | per-unit/per-app
    env       = "first"            # none | first | after-app
    platforms = { kubernetes = "80%", lambda = "20%" }
    databases = "30%"

    kubernetes_clusters = 1        # Kubernetes clusters the apps spread over
    aws_accounts        = 1        # AWS accounts the Lambda apps spread over
    aws_mounts          = "shared" # shared | per-account
    policies            = { per-app = "100%" }  # per-app | templated | legacy
    user_auth           = "root"   # root | unit: where people log in (enterprise)
  }
}
```

From the app count it builds an org (about 3 apps per team, 4 reports per
manager, as many manager layers as that takes) and gives the apps to the
models in order. The model's `namespace` says which part of an app's org path
becomes a namespace; the rest becomes folders in a `secret/` mount, then the
app (unless it has a namespace of its own), the environment where `env` puts
it, and the secret. Every app has `config/settings` and `api/key`, and one
with a database has `db/read`, `db/read-write` and `db/admin`. On community
edition each namespace becomes a cluster of its own.

The Vault settings are all optional:

| Setting | Where | Default | What it does |
|---|---|---|---|
| `identity` | cluster | `false` | People get entities, aliases and internal groups, and their policies come through the groups instead of their logins. |
| `kubernetes_clusters` | model | `1` | Kubernetes clusters the model's Kubernetes apps are spread over, each with its own auth mount `k8s-<model>-<n>`. |
| `aws_accounts` | model | `1` | AWS accounts the model's Lambda apps are spread over. |
| `aws_mounts` | model | `shared` | `shared`: one AWS auth mount `aws-<model>` for every account; `per-account`: a mount `aws-<model>-<account>` each. |
| `policies` | model | `{ per-app = "100%" }` | The share of the model's ops groups using each policy style, as percentages adding up to 100%. |
| `user_auth` | model | `unit` for `per-unit` and `per-unit/per-app`, `root` otherwise | Where people log in on enterprise: the root or their unit's namespace. |

## People and access

Every team has 2 to 8 developers, a tester and a PM. The manager above each
team, with the up to 4 teams under them and two ops engineers, is an ops
group, and ops groups are gathered 4 at a time under an ops manager. Each
secret says who may use it (`estate/access.go`):

- the app itself (`<app>`)
- its team's developers (`<team>-developers`): its config and API key, and
  the read-only database credential
- its team's tester (`<team>-testers`): its config and API key, read only
- its ops group's manager (`<group>-manager`): everything, read only
- its ops group's ops engineers (`<group>-ops`): all three database
  credentials, and its config

PMs log in but read nothing, and an ops manager has the access of all the ops
engineers in their groups.

Every app gets a login of its platform's method in the namespace holding its
secrets: a Kubernetes role, an AppRole role (VM apps), or an AWS IAM role
(Lambda apps). An ops group's legacy apps share one AppRole role, which sits
in the nearest namespace above them all. Every person gets a username and
password on the `userpass` mount wherever they log in: at the root or their
unit's namespace on enterprise, or on every community cluster holding their
teams' secrets.

## Policy styles

Every team, app and person in an ops group shares its group's style:

- **per-app** (tidy): a policy per app and environment, per team role and per
  ops group, granting exactly the access above, path by path.
- **templated**: one policy per auth mount, filled in at login from the app's
  identity (Kubernetes service-account metadata, AppRole SecretID metadata,
  or a pre-created AWS alias's metadata); ops engineers get `+` wildcards;
  people get policies templated on their entity's team when `identity` is on,
  and tidy ones when it's off.
- **legacy**: the mess real estates have. A shared AppRole with a group-wide
  wildcard, environment-wide policies on people, a broad ops grant with
  `sudo` and a near-duplicate of it, a `deny` carve-out, KV v1-style rules
  that match nothing, and a policy for an app that no longer exists. Each is
  marked in the manifest with its quirk.

```bash
vault-estate show examples/noths.xcl                  # the whole estate, as a tree
vault-estate show examples/noths.xcl -level mount     # namespace | mount | app | secret
vault-estate show examples/noths.xcl -json            # the same, as JSON
vault-estate show examples -name noths                # a customer from a folder
```

See `examples/noths.xcl` for the template. The same customer and seed
always lay out the same estate, and generate the same manifest.

## Standing up a customer

`generate` writes the customer's manifest: per cluster and namespace, its KV
v2 mounts with made-up secrets, its auth mounts with their configuration,
roles and users, its policies (rules as data, and their HCL), and its
entities and groups. `apply` writes a manifest to one empty Vault per cluster,
filling in what only Vault knows, such as mount accessors in templated
policies. It never deletes anything, and reuses a mount that already exists
with the same type, such as a dev server's `secret/`.

```bash
docker run --rm -d -p 8210:8200 hashicorp/vault:latest \
  server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200

vault-estate generate examples/noths.xcl -out noths.json
vault-estate apply -manifest noths.json -addr noths=http://127.0.0.1:8210 -token root
```

Or start the dev Vault with [jumppad](https://jumppad.dev), at
`http://localhost:8200` with root token `root` (`jumppad down` removes it):

```bash
jumppad up ./jumppad
eval "$(jumppad env)"   # VAULT_ADDR and VAULT_TOKEN
vault-estate apply -manifest noths.json
```

With no `-addr`, `apply` sends a customer on one cluster to `$VAULT_ADDR`, and
`-token` defaults to `$VAULT_TOKEN`.

Every person's username and password are in the manifest, so you can log in
as any of them (`vault login -method=userpass username=<name>`) and see the
policies they get.

A customer on more than one cluster needs one Vault, and one `-addr`, per
cluster: `apply` names any cluster without an address and writes nothing.
The enterprise customers (`bank`, `retail-group`) need Vault Enterprise for
their namespaces.

## Using the container

The image is the binary on distroless, for `linux/amd64` and `linux/arm64`.
The examples are in the image at `/examples`. Mount a folder for your own
customers and to write the manifest to, and use the host's network to reach a
Vault on localhost (Linux):

```bash
docker run --rm ghcr.io/nicholasjackson/vault-estate show /examples/noths.xcl

docker run --rm -v "$PWD:/work" -u "$(id -u)" ghcr.io/nicholasjackson/vault-estate \
  generate /examples/noths.xcl -out /work/noths.json

docker run --rm --network host -v "$PWD:/work" ghcr.io/nicholasjackson/vault-estate \
  apply -manifest /work/noths.json -addr noths=http://127.0.0.1:8210 -token root
```

## Development

```bash
make build        # bin/vault-estate
make test         # vet and unit tests
make integration  # apply startup, noths and scaleup to throwaway dev Vault containers (needs docker)
make docker       # the container image, for this machine
```

The integration tests apply `startup`, `noths` and `scaleup` to throwaway dev
Vault containers and read them back. They need docker, and the normal
`go test ./...` skips them. `VAULT_ESTATE_IMAGE` picks the Vault image
(`hashicorp/vault:latest` by default).

## Builds

`.github/workflows/build.yml` runs on every push and pull request:

- the unit and integration tests
- the binaries for Linux, macOS and Windows on amd64 and arm64, as workflow
  artifacts
- the container image, pushed to `ghcr.io/nicholasjackson/vault-estate`
  outside pull requests: `latest` and `main` from main, `<version>` and
  `<major>.<minor>` from a `v*` tag, and `sha-<commit>` always

Pushing a `v*` tag also makes a GitHub release with the binaries and their
checksums:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

## TODO

- [ ] **Access test.** Check that a Vault configured by `vault-estate apply`
  gives each principal the access its manifest intends. Real Kubernetes and
  AWS IAM logins can't happen locally, so the test may need to mint tokens
  with each principal's policies and ask Vault what they can do
  (`sys/capabilities`).
