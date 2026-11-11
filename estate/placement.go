package estate

import (
	"fmt"
	"math/rand/v2"
)

// The platforms whose apps log in through something other than AppRole: a
// Kubernetes app through its cluster's Kubernetes auth mount, and a Lambda
// app through AWS IAM auth in its account. VM and legacy apps use AppRole.
const (
	PlatformKubernetes = "kubernetes"
	PlatformLambda     = "lambda"
	PlatformVM         = "vm"
	PlatformLegacy     = "legacy"
)

// placeApps puts each Kubernetes app on one of its model's Kubernetes
// clusters and each Lambda app in one of its model's AWS accounts, gives
// each ops group to the model holding most of its apps, and apportions each
// model's policy-style mix over the groups it owns. Apps are dealt
// round-robin from a shuffled list, so every cluster and account gets apps
// when there are enough. It draws from its own stream, so the rest of the
// estate doesn't move.
func placeApps(r *rand.Rand, p *Plan) {
	byModel := map[string][]*App{}
	for _, a := range p.Apps {
		byModel[a.Model] = append(byModel[a.Model], a)
	}

	p.AWSAccounts = map[string][]string{}
	used := map[string]bool{}

	for _, m := range p.Models {
		var kube, lambda []*App
		for _, a := range byModel[m.Name] {
			switch a.Platform {
			case PlatformKubernetes:
				kube = append(kube, a)
			case PlatformLambda:
				lambda = append(lambda, a)
			}
		}

		var clusters []string
		for i := range *m.KubernetesClusters {
			clusters = append(clusters, fmt.Sprintf("k8s-%s-%d", m.Name, i+1))
		}

		for i, a := range deal(r, kube) {
			a.KubeCluster = clusters[i%len(clusters)]
		}

		var accounts []string
		for len(accounts) < *m.AWSAccounts {
			id := fmt.Sprintf("%d%011d", 1+r.IntN(9), r.Int64N(100_000_000_000))
			if !used[id] {
				used[id] = true
				accounts = append(accounts, id)
			}
		}

		p.AWSAccounts[m.Name] = accounts

		for i, a := range deal(r, lambda) {
			a.AWSAccount = accounts[i%len(accounts)]
		}
	}

	// each group belongs to the model holding most of its apps, the earlier
	// model on a tie
	owned := map[string][]*OpsGroup{}
	for _, g := range p.Groups {
		apps := map[string]int{}
		for _, team := range g.Teams {
			for _, a := range team.Apps {
				apps[a.Model]++
				a.Group = g
			}
		}

		best := 0
		for _, m := range p.Models {
			if apps[m.Name] > best {
				g.Model, best = m.Name, apps[m.Name]
			}
		}

		owned[g.Model] = append(owned[g.Model], g)
	}

	for _, m := range p.Models {
		groups := owned[m.Name]

		// validated when the plan was built, so this can't fail
		shares, _ := m.policyShares()

		var weights []int
		for _, s := range Styles {
			weights = append(weights, shares[s])
		}

		var styles []string
		for i, n := range apportion(len(groups), weights) {
			for range n {
				styles = append(styles, Styles[i])
			}
		}

		r.Shuffle(len(styles), func(i, j int) { styles[i], styles[j] = styles[j], styles[i] })

		for i, g := range groups {
			g.Style = styles[i]
		}
	}
}

// deal returns the apps in a random order, for dealing out round-robin.
func deal(r *rand.Rand, apps []*App) []*App {
	out := make([]*App, len(apps))
	for i, j := range r.Perm(len(apps)) {
		out[i] = apps[j]
	}

	return out
}

// UserAuth returns where the model's people log in on enterprise: the root
// or the unit's namespace.
func (p *Plan) UserAuth(model string) string {
	return p.Model(model).UserAuth
}
