# A dev Vault to stand a customer up on, at http://localhost:8200 with root
# token root:
#
#   jumppad up ./jumppad
#   vault-estate generate examples/noths.xcl -out noths.json
#   vault-estate apply -manifest noths.json -addr noths=http://localhost:8200 -token root
#   jumppad down
#
# One Vault is enough for a customer on one cluster, such as startup or noths.
# The enterprise examples (bank, retail-group) need a Vault Enterprise image
# and a licence for their namespaces.

variable "vault_image" {
  default     = "hashicorp/vault:latest"
  description = "the Vault image to run"
}

variable "vault_port" {
  default     = 8200
  description = "the port on localhost to reach Vault at"
}

resource "network" "local" {
  subnet = "10.10.0.0/16"
}

resource "container" "vault" {
  image {
    name = variable.vault_image
  }

  network {
    id = resource.network.local.meta.id
  }

  command = [
    "vault",
    "server",
    "-dev",
    "-dev-root-token-id=root",
    "-dev-listen-address=0.0.0.0:8200",
  ]

  port {
    local = 8200
    host  = variable.vault_port
  }

  environment = {
    VAULT_ADDR = "http://127.0.0.1:8200"
  }

  health_check {
    timeout = "60s"

    http {
      address       = "http://localhost:${variable.vault_port}/v1/sys/health"
      success_codes = [200]
    }
  }
}

output "VAULT_ADDR" {
  value = "http://localhost:${variable.vault_port}"
}

output "VAULT_TOKEN" {
  value = "root"
}
