// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/find"
)

// The navigation, as data.
//
// It was markup — nineteen list items written out twice, once per orientation
// — and markup cannot answer the three questions now being asked of it: what
// order does this person want their tabs in, which of them may this person
// actually use, and where in the documentation is the page they are looking
// at explained.
//
// So it is a table. The table is the single place a destination exists: adding
// a screen means adding a row, and the row carries its group, the permission
// it needs, and its documentation anchor. Three tests read it — one checks
// every path is served, one checks every anchor exists in the documentation,
// and one checks nothing is in the mux that is not either here or written
// down as deliberately absent.

// destination is one place a person can go.
type destination struct {
	// Key identifies it in a stored order. Stable across renames of the label,
	// because a person's saved arrangement should survive us rewording a tab.
	Key   string
	Label string
	Path  string
	Group string
	// Doc is the documentation section that explains this screen. The footer
	// link on every page points at it, so "Help" means help with what you are
	// looking at rather than help in general.
	Doc string
	// Needs is the least permission that makes this screen useful. Somebody
	// without it does not see the entry.
	//
	// Hidden rather than shown-and-refused. A menu full of doors that answer
	// "you cannot do that here" teaches people to ignore the menu, and it also
	// tells a reader exactly which administrative screens exist to go asking
	// for. The refusal still happens at the handler — this is presentation,
	// never the control.
	Needs auth.Action
}

// groups are the sections, in their default order, named for what somebody
// on a security team is doing.
var groups = []string{
	"Proving ground", // what security work was checked against evidence it did not write
	"Operations",     // what is wrong now, and what is being done about it
	"Investigation",  // what happened
	"Detection",      // what counts as wrong, and what arrives to be judged
	"Exposure",       // where the estate is weak before anything happens
	"Administration", // who may do what, and how this console is set up
	"Reference",      // how any of it works
}

// destinations is every screen, in the default order.
var destinations = []destination{
	// What has been proven, refuted and left inconclusive: the rules, the
	// thresholds and other vendors' AI, checked against evidence none of
	// them wrote. Viewing, because a proof is made to be read by whoever
	// relies on the work it is about.
	{"proofs", "Proofs", "/proving/proofs", "Proving ground", "proofs", auth.ActView},
	// Beside Proofs: closures judged again blind, whose judgements become the
	// proofs listed beside it. Viewing shows how far each review has got;
	// judging an item asks for triage, at the operation.
	{"adjudication", "Adjudication", "/proving/adjudication", "Proving ground", "proofs", auth.ActView},
	// Vendors' claims, pre-registered as tests.
	{"claims", "Claim cards", "/proving/claims", "Proving ground", "proofs", auth.ActView},

	// What is waiting and what is wrong, for everybody who signs in; where
	// a sign-in lands.
	{"today", "Today", "/today", "Operations", "start", auth.ActView},
	// Everything waiting for a person, from every part of the program, so
	// nothing waits unseen because it waited somewhere nobody opened.
	{"approvals", "Approvals", "/approvals", "Operations", "approvals", auth.ActView},
	{"findings", "Findings", "/findings", "Operations", "findings", auth.ActView},
	{"cases", "Cases", "/security/cases", "Operations", "cases", auth.ActView},
	{"risk", "Risk", "/security/risk", "Operations", "findings", auth.ActView},

	// The AI-agent story, first in what happened: what each observed agent
	// called, was refused and proposed, from the sidecar and GenAI
	// telemetry. Triage rather than view because, like Events and Hunt, it
	// reads raw telemetry — which names people's activity, pseudonymised.
	{"agents", "Agents", "/security/agents", "Investigation", "mcp", auth.ActTriage},
	// Beside Agents, under its address: where the machines that run agents
	// talked to, from the recorder's own auditd tail. The same triage gate
	// as the board it sits under, because it reads the same raw telemetry —
	// addresses, and hostnames that name people's machines.
	{"egress", "Egress", "/security/egress", "Investigation", "mcp", auth.ActTriage},
	{"events", "Events", "/security/events", "Investigation", "events", auth.ActTriage},
	{"hunt", "Hunt", "/security/hunt", "Investigation", "events", auth.ActTriage},
	{"indicators", "Indicators", "/security/indicators", "Investigation", "intelligence", auth.ActView},

	{"detections", "Detections", "/security/detections", "Detection", "detections", auth.ActView},
	{"automations", "Automations", "/security/automations", "Detection", "automations", auth.ActView},
	{"signins", "Sign-ins", "/security/signins", "Detection", "automations", auth.ActTriage},
	{"feeds", "Feeds", "/security/feeds", "Detection", "connectors", auth.ActView},

	{"vulns", "Vulnerabilities", "/security/vulns", "Exposure", "vulnerabilities", auth.ActView},
	// People and their machines, from what the company's tools say. Admin
	// only: a person's score is a file on an employee.
	{"workforce", "Workforce risk", "/workforce", "Exposure", "workforce", auth.ActGrant},

	{"people", "People", "/people", "Administration", "people", auth.ActGrant},
	// Beside People: the same people, kept in step by the identity provider.
	{"provisioning", "Provisioning", "/provisioning", "Administration", "people", auth.ActGrant},
	// Beside Provisioning: the identity provider that keeps people in step
	// is usually the one they sign in through.
	{"sso", "Single sign-on", "/sso", "Administration", "sso", auth.ActGrant},
	// View, not grant: everybody manages their own passkeys, and a screen that
	// only administrators could open would be a second factor only
	// administrators could have.
	{"passkeys", "Passkeys", "/passkeys", "Administration", "passkeys", auth.ActView},
	{"settings", "Settings", "/settings", "Administration", "settings", auth.ActGrant},
	{"logs", "Log", "/logs", "Administration", "audit", auth.ActView},

	// Find is in Reference, because it is about this console rather than
	// about what is in it — and because the box in the bar is how anybody
	// will actually reach it. The row exists so the screen is reachable on a
	// narrow window, where the bar has no room for the box.
	{"find", "Find", "/find", "Reference", "start", auth.ActView},
	{"start", "Get started", "/start", "Reference", "start", auth.ActView},
	{"profile", "You", "/profile", "Reference", "passkeys", auth.ActView},
}

// DocsBase is where the manual lives.
//
// It used to be compiled in: about 1,800 lines of Go describing every screen,
// served at /docs, with eight screenshots embedded in the binary. That made
// the documentation a release artefact — a wording fix waited for a build, and
// a screenshot went stale the moment a screen changed.
//
// It is now a site of its own, so it can be corrected the day somebody notices
// rather than the next time somebody ships. The cost is that the link target
// is no longer verifiable by compiling this program, which is what docSections
// below exists to hold on to.
const DocsBase = "https://aertun.github.io/"

// docSections is every anchor the published manual carries.
//
// The contract with the site, written down on this side of it. When the manual
// was in this repository a test could read it and prove that the Help link on
// every screen landed on a section that existed; the manual is now in another
// repository and that proof is not available at compile time.
//
// So the list is declared, a test checks every screen against it, and the site
// checks its own pages against the same list in its CI. Neither half proves the
// other, but each one fails loudly on its own side, and the failure a reader
// actually suffers — Help landing on nothing — needs both halves to be wrong.
//
// A link that lands on a heading somebody renamed is worse than no link: the
// person following it concludes the feature was removed, which is the belief
// the documentation exists to correct.
var docSections = map[string]bool{
	// One page per screen, named by the destination table above.
	"approvals": true, "audit": true, "proofs": true, "automations": true, "cases": true, "connectors": true,
	"detections": true, "events": true, "findings": true, "intelligence": true, "passkeys": true,
	"people": true, "settings": true, "sso": true, "start": true, "vulnerabilities": true, "workforce": true,

	// Guides no screen owns, because they explain a concept or a surface
	// rather than a destination. Named individually so that one quietly
	// disappearing from the site is a change somebody made on purpose.
	"install": true, "roles": true, "cli": true, "mcp": true, "security": true, "licence": true,
}

// DocURL is the address of one guide in the manual. Each guide is a page
// of its own, at /SLUG/.
func DocURL(page string) string {
	if page == "" {
		return DocsBase
	}
	return DocsBase + page + "/"
}

// docFor returns the documentation anchor for a screen key.
//
// Used by the footer on every page, so "Help" lands on the section about the
// thing in front of you. A key with no row returns the introduction, which is
// the right answer for a page that is not a navigation destination — the
// sign-in screen, a message, a conflict.
func docFor(navKey string) string {
	for _, d := range destinations {
		if d.Key == navKey {
			return d.Doc
		}
	}
	return "start"
}

// navGroup is a rendered section.
type navGroup struct {
	Name  string
	Items []navItem
	// HasCurrent is true when this group holds the screen being rendered, so
	// the template can open it and leave the rest closed.
	//
	// Server-side rather than a CSS trick or a stored preference. The group
	// you want open is the one you are in, and that is known here — which
	// means it is right on the first paint, with no flash and nothing to
	// remember. A stored open/closed state would be a preference that goes
	// stale the moment you navigate somewhere else.
	HasCurrent bool
	// Slug names the section's flyout on the rail; Icon and Short are how
	// the rail draws it. See icons.go.
	Slug, Icon, IconFilled, Short string
}

// navItem is a rendered entry.
type navItem struct {
	destination
	Current bool
	// Icon is the path of the screen's Material Symbol, and IconFilled the
	// same symbol filled, drawn for the current screen. See icons.go.
	Icon, IconFilled string
}

// navFor builds the navigation for one request.
//
// Three things decide it: what this person may do, the order they have chosen,
// and which screen they are on. All three are per-request, and none of them is
// cached — the alternative is a cache whose staleness is a permission.
func (s *Server) navigation(r *http.Request, p principal, current string) []navGroup {
	ordered := applyOrder(visibleTo(s, p), storedOrder(r))

	byGroup := map[string][]navItem{}
	hasCurrent := map[string]bool{}
	for _, d := range ordered {
		here := d.Key == current
		if here {
			hasCurrent[d.Group] = true
		}
		byGroup[d.Group] = append(byGroup[d.Group], navItem{
			destination: d, Current: here,
			Icon: iconFor(d.Key), IconFilled: filledFor(d.Key),
		})
	}
	out := make([]navGroup, 0, len(groups))
	for _, name := range groups {
		if items := byGroup[name]; len(items) > 0 {
			short := sectionShort[name]
			if short == "" {
				short = name
			}
			out = append(out, navGroup{
				Name: name, Items: items, HasCurrent: hasCurrent[name],
				Slug: sectionSlug(name), Icon: sectionPath[name], IconFilled: sectionFilled[name], Short: short,
			})
		}
	}
	return out
}

// NavOrderCookie holds a person's chosen arrangement.
const NavOrderCookie = "aertun_nav_order"

// storedOrder reads the arrangement from the request.
//
// A cookie rather than a stored preference on the server, for the same reason
// the nav position is: this is a fact about a screen somebody is looking at,
// not a fact about the store. Two people sharing an account should not fight
// over it, and it must not survive into somebody else's session.
func storedOrder(r *http.Request) []string {
	c, err := r.Cookie(NavOrderCookie)
	if err != nil {
		return nil
	}
	raw, err := url.QueryUnescape(c.Value)
	if err != nil {
		return nil
	}
	var out []string
	for _, key := range strings.Split(raw, ",") {
		if key = strings.TrimSpace(key); key != "" {
			out = append(out, key)
		}
	}
	return out
}

// applyOrder sorts destinations by a stored arrangement.
//
// Anything the arrangement does not mention keeps its position relative to the
// others and goes last within its group. That is what makes a saved order
// survive a new screen being added: the arrangement is a preference about the
// screens somebody knew about, and a screen they have never seen should appear
// rather than be silently hidden by an old cookie.
func applyOrder(in []destination, order []string) []destination {
	if len(order) == 0 {
		return in
	}
	at := make(map[string]int, len(order))
	for i, key := range order {
		at[key] = i
	}
	out := append([]destination(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		pi, oki := at[out[i].Key]
		pj, okj := at[out[j].Key]
		switch {
		case oki && okj:
			return pi < pj
		case oki:
			return true
		case okj:
			return false
		}
		return false // both unknown: keep the table's order
	})
	return out
}

// handleNavOrder moves one destination up or down.
//
// Buttons rather than dragging. WCAG 2.2 2.5.7 says no function may require a
// drag gesture, and this project's answer has always been that reordering is
// something you press or type — which is also faster, works on a phone, and
// works for somebody using only a keyboard.
func (s *Server) handleNavOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	// Start from what this person can see, in their current arrangement, so a
	// move is relative to what is in front of them rather than to a table they
	// have never seen.
	current := applyOrder(visibleTo(s, p), storedOrder(r))
	keys := make([]string, 0, len(current))
	for _, d := range current {
		keys = append(keys, d.Key)
	}

	switch {
	case r.FormValue("reset") != "":
		s.clearCookie(w, r, NavOrderCookie)
		http.Redirect(w, r, "/profile#arrangement", http.StatusSeeOther)
		return
	case r.FormValue("key") != "":
		keys = move(keys, r.FormValue("key"), r.FormValue("direction"))
	}
	// Back to the tab that moved, with its group open.
	back := "/profile#arrangement"
	if k := r.FormValue("key"); groupOf(k) != "" {
		back = "/profile?moved=" + url.QueryEscape(k) + "#tab-" + url.PathEscape(k)
	}

	http.SetCookie(w, &http.Cookie{
		Name: NavOrderCookie, Value: url.QueryEscape(strings.Join(keys, ",")),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || s.behindTLSProxy(), MaxAge: 365 * 24 * 3600,
	})
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// move shifts one key one place, within its own group.
//
// Within the group, because the groups are the structure and a tab that could
// wander out of its section would leave somebody with Media under
// Administration wondering what they had done. Somebody who wants a different
// structure wants a different product, and this is a preference rather than a
// redesign.
func move(keys []string, key, direction string) []string {
	group := groupOf(key)
	if group == "" {
		return keys
	}
	// Positions of this group's members, in the current arrangement.
	var idx []int
	for i, k := range keys {
		if groupOf(k) == group {
			idx = append(idx, i)
		}
	}
	for n, i := range idx {
		if keys[i] != key {
			continue
		}
		var swap int
		switch direction {
		case "up":
			if n == 0 {
				return keys
			}
			swap = idx[n-1]
		case "down":
			if n == len(idx)-1 {
				return keys
			}
			swap = idx[n+1]
		default:
			return keys
		}
		keys[i], keys[swap] = keys[swap], keys[i]
		return keys
	}
	return keys
}

func groupOf(key string) string {
	for _, d := range destinations {
		if d.Key == key {
			return d.Group
		}
	}
	return ""
}

// screenAreas are the screens that belong to an area, and are shown to
// whoever holds that area. A role granted on "/" covers them all.
var screenAreas = map[string]string{
	"findings": auth.AreaSecurity, "risk": auth.AreaSecurity, "cases": auth.AreaSecurity,
	"events": auth.AreaSecurity, "hunt": auth.AreaSecurity, "detections": auth.AreaSecurity,
	"agents": auth.AreaSecurity, "egress": auth.AreaSecurity,
	"indicators": auth.AreaSecurity, "vulns": auth.AreaSecurity, "workforce": auth.AreaSecurity,
	"automations": auth.AreaSecurity, "signins": auth.AreaSecurity, "feeds": auth.AreaSecurity,
	"logs": auth.AreaLog,
}

// resource is what a screen's entry is checked against.
func (d destination) resource() string {
	if a, ok := screenAreas[d.Key]; ok {
		return a
	}
	return "/"
}

// visibleTo is the destinations a principal may use.
func visibleTo(s *Server, p principal) []destination {
	out := make([]destination, 0, len(destinations))
	for _, d := range destinations {
		if d.Key != "today" && s.Policy != nil && !s.Policy.Evaluate(p.Name, d.Needs, d.resource()).Allowed {
			continue
		}
		out = append(out, d)
	}
	return out
}

// clearCookie expires one of the preference cookies.
//
// A method rather than a free function only so it can ask the server whether
// Secure applies. A deletion is matched by name, path and domain rather than
// by attributes, so this is about the set of attributes staying identical
// across the two places a cookie is written and unwritten, not about the
// deletion itself needing protecting.
func (s *Server) clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || s.behindTLSProxy(),
	})
}

// Screens is the navigation, in the shape the finder takes.
//
// # Why the synonyms live here
//
// A destination's Label is what it is called; Also is what somebody looking
// for it would type. The two are different often enough to matter: nobody
// hunting for the translation screen searches "languages" first, and nobody
// looking for permissions searches "access".
//
// They sit beside the table rather than in the finder because they are a
// property of the screen. A finder holding its own list of other words for
// each screen is a second table that drifts from this one the first time
// something is renamed — and the symptom is a screen that stops being findable
// under the word everybody uses for it.
func Screens() []find.Destination {
	also := map[string][]string{
		"today":        {"home", "dashboard", "waiting"},
		"approvals":    {"approve", "decide", "second person", "four eyes"},
		"findings":     {"alert", "queue", "triage", "detection"},
		"cases":        {"incident", "response", "playbook", "act"},
		"risk":         {"score", "priority", "exposure"},
		"events":       {"log", "telemetry", "raw"},
		"hunt":         {"search", "query", "baseline", "stack"},
		"agents":       {"ai", "bot", "mcp", "llm", "genai", "tool call", "sidecar"},
		"egress":       {"outbound", "network", "connect", "destination", "traffic", "socket"},
		"indicators":   {"ioc", "intelligence", "threat", "hash", "domain"},
		"detections":   {"rule", "sigma", "tuning", "suppression", "ring"},
		"automations":  {"soar", "playbook", "rule", "response"},
		"signins":      {"login", "travel", "location", "unlock"},
		"feeds":        {"ingest", "webhook", "ssf", "caep", "connector", "source"},
		"vulns":        {"cve", "ssvc", "vex", "patch", "advisory"},
		"workforce":    {"device", "estate", "employee", "compliance", "machine"},
		"people":       {"user", "account", "role", "permission", "grant", "invite"},
		"provisioning": {"scim", "identity provider", "group"},
		"sso":          {"oidc", "saml", "entra", "okta", "google"},
		"passkeys":     {"passkey", "webauthn", "2fa", "mfa", "security key", "login"},
		"settings":     {"configuration", "config", "option", "preference"},
		"logs":         {"audit", "log", "trail", "record"},
		"start":        {"help", "documentation", "docs", "guide", "getting started"},
		"profile":      {"me", "my account", "sign out", "session"},
	}
	out := make([]find.Destination, 0, len(destinations))
	for _, d := range destinations {
		out = append(out, find.Destination{
			Title: d.Label, Path: d.Path, Group: d.Group, Also: also[d.Key],
		})
	}
	return out
}
