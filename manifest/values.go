package manifest

import (
	"math/rand/v2"
	"strings"

	"github.com/nicholasjackson/vault-estate/estate"
)

// values makes up secret values and passwords from a stream of its own,
// consumed in the manifest's fixed order, so they are the same per seed.
type values struct {
	r *rand.Rand
}

func newValues(seed int) *values {
	return &values{r: rand.New(rand.NewPCG(uint64(seed), 0x5ec7e7))}
}

const (
	lower        = "abcdefghijklmnopqrstuvwxyz"
	alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	hexDigits    = "0123456789abcdef"
)

func (v *values) chars(set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[v.r.IntN(len(set))]
	}

	return string(b)
}

// password is a made-up password.
func (v *values) password() string {
	return v.chars(alphanumeric, 24)
}

// settings are the keys an app's configuration may have, each with the
// values it may take.
var settings = []struct {
	key    string
	values []string
}{
	{"log_level", []string{"debug", "info", "warn", "error"}},
	{"region", []string{"eu-west-1", "eu-west-2", "us-east-1", "us-west-2", "ap-southeast-2"}},
	{"timeout_ms", []string{"500", "1000", "2500", "5000", "30000"}},
	{"cache_ttl", []string{"30s", "5m", "15m", "1h"}},
	{"feature_flags", []string{"new-checkout", "dark-mode,beta-search", "none", "fast-path"}},
	{"max_connections", []string{"10", "25", "50", "100"}},
	{"retry_attempts", []string{"0", "3", "5"}},
}

var apiKeyPrefixes = []string{"sk_live", "pk_live", "key", "api", "tok"}

// secret makes up a secret's keys and values: a username and password for a
// database credential, a few settings for configuration, and an API key.
func (v *values) secret(sec estate.Secret) map[string]string {
	switch sec.Thing {
	case "db":
		user := strings.NewReplacer("-", "_").Replace(sec.App.Name + "_" + sec.Name)

		return map[string]string{
			"username": user + "_" + v.chars(lower, 6),
			"password": v.password(),
		}
	case "api":
		return map[string]string{
			"api_key": apiKeyPrefixes[v.r.IntN(len(apiKeyPrefixes))] + "_" + v.chars(hexDigits, 32),
		}
	default:
		out := map[string]string{}
		for _, i := range v.r.Perm(len(settings))[:2+v.r.IntN(3)] {
			s := settings[i]
			out[s.key] = s.values[v.r.IntN(len(s.values))]
		}

		return out
	}
}
