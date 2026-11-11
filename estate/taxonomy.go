package estate

import (
	"fmt"
	"sort"
)

// Taxonomy is an industry's business capabilities, which teams are named
// after: domains (the units under the CTO), the areas in each domain, and
// the capabilities in each area. The CTO has at most Span units, and each of
// them at most Span groups, so only the first Span domains are used and each
// has at least Span areas.
type Taxonomy struct {
	Domains []Domain
}

// Domain is a part of the business, i.e. commerce.
type Domain struct {
	Name  string
	Areas []Area
}

// Area is a group of related capabilities in a domain, i.e. checkout.
type Area struct {
	Name         string
	Capabilities []string
}

// qualifiers split a capability between several teams in a large org, i.e.
// checkout-web and checkout-api
var qualifiers = []string{"web", "api", "mobile", "platform", "data", "ops", "integrations", "experience"}

// Industries are the taxonomies, by industry.
var Industries = map[string]Taxonomy{
	"retail": {Domains: []Domain{
		{Name: "commerce", Areas: []Area{
			{Name: "discovery", Capabilities: []string{"search", "browse", "recommendations", "product-pages", "reviews"}},
			{Name: "checkout", Capabilities: []string{"basket", "payments", "promotions", "gift-cards", "order-confirmation"}},
			{Name: "catalogue", Capabilities: []string{"product-catalogue", "pricing", "content", "media", "merchandising"}},
			{Name: "marketplace", Capabilities: []string{"partner-onboarding", "partner-portal", "partner-payouts", "listings"}},
		}},
		{Name: "customer", Areas: []Area{
			{Name: "accounts", Capabilities: []string{"identity", "customer-accounts", "preferences", "consent"}},
			{Name: "engagement", Capabilities: []string{"loyalty", "notifications", "email", "personalisation", "campaigns"}},
			{Name: "service", Capabilities: []string{"contact-centre", "returns", "order-tracking", "chat"}},
			{Name: "apps", Capabilities: []string{"ios-app", "android-app", "mobile-api", "app-config"}},
		}},
		{Name: "supply-chain", Areas: []Area{
			{Name: "inventory", Capabilities: []string{"stock", "replenishment", "forecasting", "suppliers"}},
			{Name: "fulfilment", Capabilities: []string{"orders", "warehouse", "picking", "delivery", "carriers"}},
			{Name: "stores", Capabilities: []string{"point-of-sale", "store-ops", "click-and-collect", "workforce"}},
			{Name: "sourcing", Capabilities: []string{"buying", "supplier-portal", "quality", "sustainability"}},
		}},
		{Name: "corporate", Areas: []Area{
			{Name: "finance", Capabilities: []string{"ledger", "invoicing", "tax", "reconciliation"}},
			{Name: "data", Capabilities: []string{"analytics", "reporting", "data-platform", "experimentation"}},
			{Name: "platform", Capabilities: []string{"cloud-platform", "observability", "security", "ci-cd"}},
			{Name: "people", Capabilities: []string{"hr-systems", "payroll", "recruitment", "learning"}},
		}},
	}},

	// modelled on BIAN's service domains
	"banking": {Domains: []Domain{
		{Name: "retail-banking", Areas: []Area{
			{Name: "accounts", Capabilities: []string{"current-account", "savings-account", "account-servicing", "statements"}},
			{Name: "cards", Capabilities: []string{"card-authorization", "card-transactions", "card-collections", "issued-devices"}},
			{Name: "lending", Capabilities: []string{"consumer-loan", "mortgage-loan", "credit-decisioning", "collections"}},
			{Name: "channels", Capabilities: []string{"online-banking", "mobile-banking", "contact-centre", "branch-operations"}},
		}},
		{Name: "wealth", Areas: []Area{
			{Name: "investments", Capabilities: []string{"investment-portfolio", "securities-position", "instrument-valuation", "trade-confirmation"}},
			{Name: "advice", Capabilities: []string{"financial-planning", "customer-offer", "product-directory", "suitability"}},
			{Name: "custody", Capabilities: []string{"custody-administration", "corporate-actions", "securities-settlement"}},
			{Name: "private-banking", Capabilities: []string{"relationship-management", "client-onboarding", "lombard-lending"}},
		}},
		{Name: "corporate-banking", Areas: []Area{
			{Name: "payments", Capabilities: []string{"payment-order", "payment-execution", "correspondent-banking", "cheque-processing"}},
			{Name: "trade-finance", Capabilities: []string{"letter-of-credit", "bank-guarantee", "documentary-collection"}},
			{Name: "cash-management", Capabilities: []string{"liquidity", "cash-pooling", "account-reconciliation"}},
			{Name: "corporate-lending", Capabilities: []string{"corporate-loan", "syndicated-loan", "collateral-administration"}},
		}},
		{Name: "enterprise", Areas: []Area{
			{Name: "fraud", Capabilities: []string{"fraud-detection", "fraud-resolution", "transaction-monitoring"}},
			{Name: "compliance", Capabilities: []string{"regulatory-reporting", "regulatory-compliance", "know-your-customer", "anti-money-laundering"}},
			{Name: "risk", Capabilities: []string{"credit-risk", "market-risk", "operational-risk", "liquidity-risk"}},
			{Name: "core", Capabilities: []string{"party-reference-data", "document-services", "position-keeping", "customer-case"}},
			{Name: "platform", Capabilities: []string{"cloud-platform", "observability", "security", "ci-cd"}},
		}},
	}},

	"saas": {Domains: []Domain{
		{Name: "product", Areas: []Area{
			{Name: "core-app", Capabilities: []string{"workspaces", "editor", "collaboration", "files", "projects"}},
			{Name: "integrations", Capabilities: []string{"public-api", "webhooks", "marketplace", "connectors"}},
			{Name: "mobile", Capabilities: []string{"ios-app", "android-app", "offline-sync"}},
			{Name: "admin", Capabilities: []string{"admin-console", "permissions", "sso", "usage"}},
		}},
		{Name: "growth", Areas: []Area{
			{Name: "acquisition", Capabilities: []string{"signup", "onboarding", "trials", "website"}},
			{Name: "monetisation", Capabilities: []string{"billing", "subscriptions", "pricing", "invoicing"}},
			{Name: "engagement", Capabilities: []string{"notifications", "email", "in-app-messaging", "lifecycle"}},
			{Name: "sales", Capabilities: []string{"crm", "quotes", "partner-program", "enterprise-onboarding"}},
		}},
		{Name: "platform", Areas: []Area{
			{Name: "infrastructure", Capabilities: []string{"cloud-platform", "networking", "storage", "compute"}},
			{Name: "reliability", Capabilities: []string{"observability", "incident-response", "performance"}},
			{Name: "security", Capabilities: []string{"identity", "access-management", "audit-log", "compliance"}},
			{Name: "developer-experience", Capabilities: []string{"ci-cd", "build-tools", "internal-portal"}},
		}},
		{Name: "data", Areas: []Area{
			{Name: "analytics", Capabilities: []string{"product-analytics", "reporting", "dashboards"}},
			{Name: "ml", Capabilities: []string{"search", "recommendations", "ml-platform", "ai-assistant"}},
			{Name: "data-platform", Capabilities: []string{"pipelines", "warehouse", "data-quality"}},
			{Name: "insights", Capabilities: []string{"usage-metrics", "forecasting", "customer-health"}},
		}},
	}},

	"fintech": {Domains: []Domain{
		{Name: "payments", Areas: []Area{
			{Name: "acceptance", Capabilities: []string{"card-acquiring", "payment-gateway", "checkout-sdk", "merchant-onboarding"}},
			{Name: "money-movement", Capabilities: []string{"transfers", "payouts", "fx", "settlement"}},
			{Name: "wallets", Capabilities: []string{"wallet", "virtual-cards", "top-ups", "rewards"}},
			{Name: "issuing", Capabilities: []string{"card-issuing", "card-controls", "disputes"}},
		}},
		{Name: "lending", Areas: []Area{
			{Name: "origination", Capabilities: []string{"applications", "credit-decisioning", "underwriting", "offers"}},
			{Name: "servicing", Capabilities: []string{"repayments", "collections", "statements", "hardship"}},
			{Name: "partners", Capabilities: []string{"broker-api", "partner-portal", "affiliates"}},
			{Name: "credit", Capabilities: []string{"credit-scoring", "credit-limits", "risk-models"}},
		}},
		{Name: "platform", Areas: []Area{
			{Name: "core", Capabilities: []string{"ledger", "accounts", "identity", "notifications"}},
			{Name: "infrastructure", Capabilities: []string{"cloud-platform", "observability", "ci-cd", "security"}},
			{Name: "data", Capabilities: []string{"data-platform", "analytics", "reporting", "ml-platform"}},
			{Name: "security", Capabilities: []string{"access-management", "secrets", "audit-log"}},
		}},
		{Name: "risk", Areas: []Area{
			{Name: "fraud", Capabilities: []string{"fraud-detection", "transaction-monitoring", "chargebacks"}},
			{Name: "compliance", Capabilities: []string{"kyc", "aml", "regulatory-reporting", "sanctions-screening"}},
			{Name: "credit-risk", Capabilities: []string{"exposure", "provisioning", "stress-testing"}},
			{Name: "controls", Capabilities: []string{"internal-audit", "policy", "incident-management"}},
		}},
	}},
}

// IndustryNames returns the industries, sorted.
func IndustryNames() []string {
	var ns []string
	for n := range Industries {
		ns = append(ns, n)
	}

	sort.Strings(ns)

	return ns
}

// capabilities returns the domain's capabilities, taking one from each area
// in turn, so the most important of each come first.
func (d Domain) capabilities() []string {
	var out []string
	for i := 0; ; i++ {
		added := false
		for _, a := range d.Areas {
			if i < len(a.Capabilities) {
				out = append(out, a.Capabilities[i])
				added = true
			}
		}

		if !added {
			return out
		}
	}
}

// capabilities returns every capability, one from each domain in turn.
func (t Taxonomy) capabilities() []string {
	var lists [][]string
	for _, d := range t.Domains {
		lists = append(lists, d.capabilities())
	}

	var out []string
	for i := 0; ; i++ {
		added := false
		for _, l := range lists {
			if i < len(l) {
				out = append(out, l[i])
				added = true
			}
		}

		if !added {
			return out
		}
	}
}

// namer hands out unique names: a name already used gets a number.
type namer map[string]bool

func (n namer) name(base string) string {
	name := base
	for i := 2; n[name]; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}

	n[name] = true

	return name
}

// pool returns n team names from capabilities: each capability once, then
// each with a qualifier, then numbered.
func pool(capabilities []string, n int) []string {
	out := append([]string(nil), capabilities...)
	for _, q := range qualifiers {
		for _, c := range capabilities {
			out = append(out, c+"-"+q)
		}
	}

	for i := 2; len(out) < n; i++ {
		for _, c := range capabilities {
			out = append(out, fmt.Sprintf("%s-%d", c, i))
		}
	}

	return out[:n]
}

// nameOrg names the org's units, managers and teams from the taxonomy,
// by how deep the org is:
//
//	depth 1   teams are capabilities
//	depth 2   units are domains, teams their capabilities
//	depth 3   units are domains, then areas, teams the area's capabilities
//	depth 4+  units are domains, then areas, then the area's capabilities,
//	          with each capability's teams named capability-qualifier;
//	          any layers between areas and capabilities are numbered
func nameOrg(root *Node, t Taxonomy) {
	used := namer{}
	depth := level(root.Teams()[0])

	if depth == 1 {
		names := pool(t.capabilities(), len(root.Children))
		for i, team := range root.Children {
			team.Name = used.name(names[i])
		}

		return
	}

	for i, unit := range root.Children {
		domain := t.Domains[i%len(t.Domains)]
		unit.Name = used.name(domain.Name)

		if depth == 2 {
			teams := unit.Teams()
			names := pool(domain.capabilities(), len(teams))
			for j, team := range teams {
				team.Name = used.name(names[j])
			}

			continue
		}

		for j, group := range unit.Children {
			area := domain.Areas[j%len(domain.Areas)]
			group.Name = used.name(area.Name)

			if depth == 3 {
				teams := group.Teams()
				names := pool(area.Capabilities, len(teams))
				for k, team := range teams {
					team.Name = used.name(names[k])
				}

				continue
			}

			nameUnderArea(group, area, depth, used)
		}
	}
}

// nameUnderArea names what's under an area in an org 4 or more deep: the
// managers just above the teams are the area's capabilities, their teams
// capability-qualifier, and any layers in between are numbered after the
// area.
func nameUnderArea(area *Node, a Area, depth int, used namer) {
	// the managers just above the teams, left to right
	var managers []*Node
	var walk func(n *Node, level int)
	walk = func(n *Node, level int) {
		if level == depth-1 {
			managers = append(managers, n)
			return
		}

		for _, c := range n.Children {
			if level+1 < depth-1 {
				c.Name = used.name(area.Name)
			}

			walk(c, level+1)
		}
	}

	walk(area, 2)

	names := pool(a.Capabilities, len(managers))
	for i, m := range managers {
		m.Name = used.name(names[i])

		for j, team := range m.Children {
			team.Name = used.name(m.Name + "-" + qualifiers[j%len(qualifiers)])
		}
	}
}

// level is how many layers below the CTO the node is.
func level(n *Node) int {
	l := 0
	for x := n; x.Parent != nil; x = x.Parent {
		l++
	}

	return l
}
