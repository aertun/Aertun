// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package admin serves the editing interface.
//
// # Why this is server-rendered HTML
//
// ATAG 2.0 says the plain thing out loud: a web-based authoring tool "may rely
// on user agent features such as keyboard navigation, find functions, display
// preferences, and undo features" to meet its criteria. A form-and-links admin
// inherits all of that from the browser, correctly, for nothing. A single-page
// app reimplements each one and usually gets at least one wrong — focus after
// navigation, the back button, find-in-page across virtualised lists.
//
// The other reasons point the same way. aertun is one static binary in a
// scratch image with no dependencies; adding a JavaScript build would bring a
// node toolchain, several hundred transitive packages, and a bundle larger than
// the entire program. For a security console, shipping a framework to render
// a form would be an odd thing to do.
//
// So: HTML over HTTP, forms that work with scripting disabled, and no build
// step. Progressive enhancement, not degradation.
//
// # Accessibility is structural here
//
// The console must be usable by a disabled analyst, which is the half that
// gets skipped because the people who build admin panels are rarely the
// people locked out of them.
//
// Concretely, and each of these is a thing that is normally wrong:
//
//   - Every control is a real button or link, so it is reachable and operable by
//     keyboard without a single line of script.
//   - Focus is always visible, at 3:1 contrast and a 2px perimeter (WCAG 2.2
//     2.4.13), and never hidden behind a sticky bar (2.4.11).
//   - No action requires dragging (2.5.7). Reordering is a number you type,
//     which is also faster.
//   - Targets are at least 24x24 CSS pixels (2.5.8).
//   - Authentication is pasting a token. No puzzle, no image recognition, no
//     transcription — those are cognitive function tests and 3.3.8 prohibits
//     them.
//   - Status messages announce themselves without stealing focus.
//   - Colour never carries meaning alone; every state has a word.
//
// # Preview
//
// A.3.7.1 wants a preview rendered by a real in-market user agent rather than an
// approximation. So preview serves the actual page to the actual browser instead
// of drawing a picture of it in a panel.
package admin

import (
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/clientip"
	"github.com/aertun/aertun/internal/dpop"
	"github.com/aertun/aertun/internal/enrol"
	"github.com/aertun/aertun/internal/icons"
	"github.com/aertun/aertun/internal/lockout"
	"github.com/aertun/aertun/internal/oauthas"
	"github.com/aertun/aertun/internal/throttle"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aertun/aertun/internal/auth"
)

//go:embed assets/*
var assets embed.FS

// Server holds everything a request needs.
type Server struct {
	// flashKey signs the messages this server puts in a redirect, so a link
	// from anywhere else cannot make a screen say something. See flash.go.
	flashKey []byte

	Policy *auth.Policy
	Tokens *auth.TokenStore
	// LoadAudit reads the audit log. Nil means the log page says it has no
	// access rather than showing an empty list, because an empty list and no
	// access look identical and mean opposite things.
	//
	// A function rather than a path: this process does not know where the log
	// lives, and after the writer was separated out it deliberately must not
	// open it for writing. Reading is all it is given.
	LoadAudit func() ([]audit.Event, error)
	// ResolvePrincipal turns a pseudonym back into a name, for principals this
	// store knows. It cannot reverse the HMAC — it computes forward for each
	// known principal and matches — so somebody the policy has never heard of
	// stays opaque, which is the right outcome rather than a limitation.
	ResolvePrincipal func(pseudonym string) string
	// LogSeparated reports whether the writer runs as another account, so the
	// page can say what the record is worth rather than implying it.
	LogSeparated bool

	// Settings gives the admin the store's configuration.
	Settings *Settings
	// Version is the build's version, for documents the admin exports.
	Version string
	// Told tells the webhooks what happened to the live site — published,
	// rolled-back, scheduled — after the fact; nil tells nobody. The same
	// events the command line sends, so a receiver does not depend on
	// which interface somebody used.
	Told func(event, commit string, pages []string)
	// idle is when each browser session was last used (idle.go).
	idle idleClock
	// SCIM is provisioning from an identity provider. See scimadmin.go.
	SCIM *SCIMAdmin
	// Inbound answers /feeds/NAME: events other systems push here, each
	// proving where it came from rather than holding a session.
	Inbound http.Handler
	// Feeds is the Feeds screen. See feeds.go.
	Feeds *FeedsAdmin
	// SignInRisk judges each sign-in as it is made (see automations.go);
	// Automations are the rules and their history. A session they hold
	// back is confirmed with a passkey or a fresh single sign-on, never a
	// code sent by email (SP 800-63B-4 3.1.3.1 forbids email for this).
	SignInRisk  func(SignInFacts) SignInVerdict
	Automations *AutomationsAdmin
	// Enrol holds the one-time links that add a person's passkey
	// (enrolment.go).
	Enrol *enrol.Store
	// Lockout is smart lockout for the failures that belong to an account
	// (lockout.go).
	Lockout *lockout.Store
	// Dual is the privileged changes waiting for a second administrator
	// (dual.go).
	Dual *Dual
	// MFAFrom is when two factors became compulsory for every person here.
	// Zero, the default, is always: an installation is given a grace only
	// by setting it, and only before it, is one factor let through.
	MFAFrom time.Time
	// SessionPlace says where a request comes from, for binding sessions;
	// SessionMovedTo puts a session seen elsewhere to the rules; Reported
	// is a person saying a sign-in was not them; SignInSignal raises one
	// more signal about a person's sign-in, such as verification failing.
	SessionPlace   func(addr, agent string) SessionContext
	SessionMovedTo func(SessionMove) SignInVerdict
	Reported       func(principal, session string)
	SignInSignal   func(principal, kind, detail string)

	// Findings is the finding register: what the producers recorded, with
	// the audit log's decisions applied.
	Findings *Findings
	// Proving is the proving ground's operations (proving.go).
	Proving *ProvingGround

	// Workforce is the estate: what the company's tools say about its
	// people and machines, joined and scored.
	Workforce *Workforce

	// Reminders tells people what the estate says they still have to do.
	Reminders *Reminders

	// Detections is the rules: what each has been worth, its ring, and
	// what is suppressed.
	Detections *Detections
	// Vulns is the vulnerability workbench. Nil means none was wired.
	Vulns *Vulns
	// Cases is the incident store. Nil means none was wired.
	Cases *Cases
	// Indicators is the indicator store. Nil means none was wired.
	Indicators *Indicators
	// People gives the address each identifier is known by: what joins
	// one person across platforms. Nil means nobody is joined.
	People func() map[string]string

	// Events is the telemetry store.
	Events *Events
	proofs *dpop.Replays
	// Profile holds what people say about themselves — a display name and a
	// way to reach them, and nothing else. Nil means the screen shows their
	// permissions and sessions and offers no details to edit.
	Profile *Profile
	// ReloadTokens re-reads the credential store when it has changed on disk.
	// Nil means never, which is only right for a test.
	ReloadTokens func()
	// Throttle slows repeated authentication failures. Nil means no
	// throttling, which is only right in tests: the host wires one in from
	// configuration, and a nil check here rather than a panic means a caller
	// who forgets gets an unthrottled server rather than a crashed one — so
	// the CLI is where the wiring is asserted, by a test that walks it.
	Throttle *throttle.Limiter
	// OnAuthFailure is called when the alerting threshold is crossed, so the
	// host can write an audit record. The admin package does not open the
	// audit log itself: it does not know where it lives, and after the
	// separated-writer work it deliberately must not.
	OnAuthFailure func(source string, failures int)
	tpl           *template.Template

	// SAML is single sign-on through SAML identity providers; nil when the
	// build was started without it. See samlauth.go.
	SAML      *SAMLAdmin
	samlState samlState

	// OIDC, when an identity provider is configured. Nil means the only way in
	// is a token, which is the default and is a complete configuration.
	OIDC *OIDC
	// SaveTokens persists a session minted after an OIDC sign-in, so it
	// survives a restart and so revoking it is possible from the CLI.
	SaveTokens func(*auth.TokenStore) error
	// Passkeys is the registered credential set, or nil on a deployment that
	// does not offer them. See passkeys.go for why this is the one screen in
	// the program that serves a script.
	Passkeys *Passkeys
	// UpdatePolicy applies an access change to the policy as it is stored
	// now, under its lock, and returns the policy as written. The change is
	// made to the stored copy rather than to the one this server read at the
	// start of the request, so a revocation made on the command line or by
	// provisioning in between is never written back over. Nil changes only
	// the copy in memory, which is what a test without a store wants.
	UpdatePolicy func(change func(*auth.Policy) error) (*auth.Policy, error)
	// Audit records an action. The admin does not open the audit log itself:
	// it does not know where the log lives, and since the writer was separated
	// out it must not.
	Audit func(action, resource string, detail map[string]string)
	// AuditAgent records what an agent did, as an AI principal: the exchange
	// that mints an on-behalf-of credential writes here, so the record
	// carries an agent's kind and name rather than a person's. Nil records
	// nothing, which is only right in a test.
	AuditAgent func(action, resource, agent string, detail map[string]string)
	// Origin is where people and programs reach this server: admin.base_url,
	// as it was when the server started. It is the one address enrolment
	// links, feeds, the token exchange's audience and the DPoP proofs it
	// checks all name, so behind a proxy they agree with each other and
	// with the OAuth metadata. Empty means it was not set, and each
	// request's own address stands in — right on a laptop or a LAN, and
	// the reason to set it behind anything that rewrites Host.
	Origin string
	// RunKey returns the store's caveat-minting key (the file beside the
	// registry, cmd/aertun's agents.key), for the exchange to verify the run
	// credential an agent presents and to mint the caveats of the token it
	// issues. Nil means no on-behalf-of token can be minted, which the
	// exchange says rather than resolving to issue one without caveats.
	RunKey func() ([]byte, error)
	// Consents is the consent register the authorization server writes
	// (internal/oauthas). The exchange reads it, because a token minted
	// under a consent the register no longer honours would be a delegation
	// nobody agreed to.
	Consents oauthas.Store
	// OnSignIn records an authentication. Separate from the handler so the
	// audit log stays the host's concern.
	OnSignIn func(principal, tokenID string)

	// Reload re-reads credentials and access rules from disk.
	//
	// Without it the server answers from whatever it read at startup, and a
	// revoked token keeps working until somebody restarts the process. That is
	// the same failure as a session outliving its parent: revocation that does
	// not revoke, with a window measured in however long the server has been
	// up. A newly granted role is invisible for just as long, which is the same
	// bug in the direction people notice.
	Reload func() (*auth.Policy, *auth.TokenStore, error)

	// The live stream's semaphore (live.go): liveSlots bounds how many
	// concurrent /live connections this process holds, and liveOnce makes it
	// once per server however the server was built. Made lazily rather than
	// in New because a Server assembled by hand — a test, an embedding — is
	// as entitled to a bounded stream as one that went through the
	// constructor.
	liveSlots chan struct{}
	liveOnce  sync.Once
}

// refresh pulls current credentials and rules before a decision.
//
// Called on every request that authenticates or authorises. Re-reading two small
// JSON files per request is not the bottleneck here, and the alternative is a
// cache whose staleness is a security property.
func (s *Server) refresh() {
	if s.Reload == nil {
		return
	}
	if pol, toks, err := s.Reload(); err == nil {
		if pol != nil {
			s.Policy = pol
		}
		if toks != nil {
			s.Tokens = toks
		}
	}
}

// New builds the server and parses the admin templates once.
//
// html/template rather than Aertun's own engine, and the distinction matters.
// aertun's language is deliberately powerless because *users* write in it and
// user templates are an injection surface. These templates are ours, shipped in
// the binary, and never author-supplied — so the stdlib's contextual escaping is
// exactly right and there is no surface to remove.
func New(p *auth.Policy, ts *auth.TokenStore) (*Server, error) {
	t, err := template.New("").Funcs(template.FuncMap{
		"icon":      uiIcon,
		"toneicon":  toneIcon,
		"iconNames": icons.Names,
		// signedOutIcon is the mark in the built-in colours, inline, for the
		// pages somebody sees before signing in: /icon.svg carries the
		// operator's colour and is served only to the signed in, so without
		// this the browser asks for /favicon.ico and is told 401.
		"signedOutIcon": func() template.URL {
			return template.URL("data:image/svg+xml," + url.PathEscape(MarkSVG(MarkFirstColour)))
		},
		"pct": func(f float64) float64 { return f * 100 },
		// sentence capitalises the first letter, for a word stored in
		// lower case and shown on its own: a severity, a state.
		"sentence": func(v any) string {
			s := fmt.Sprint(v)
			if s == "" {
				return s
			}
			r, n := utf8.DecodeRuneInString(s)
			return string(unicode.ToUpper(r)) + s[n:]
		},
		// severities is the order severities are listed in: worst first,
		// whatever order a map would range them in.
		"severities": func() []string { return []string{"critical", "high", "medium", "low", "info"} },
		// plural is a count with its noun: "1 advisory", "8 advisories".
		"plural": countOf,
		// fixparts splits a fix into the command to run and the words
		// after its shell comment, so the words are read as words.
		"fixparts": fixParts,
		// deref reads a yes or no a tool may not have given; the template
		// checks for nil before calling it.
		"deref": func(b *bool) bool { return b != nil && *b },
		"short": func(id string) string {
			if len(id) > 12 {
				return id[:12]
			}
			return id
		},
		// A moment, stated rather than described relative to now. "ago" is
		// right for history and wrong for a schedule: a publication set for
		// next Tuesday rendered through it reads "just now", because
		// time.Since of a future instant is negative and every branch below
		// assumes it is not.
		"when": func(unix int64) string {
			if unix == 0 {
				return "—"
			}
			return time.Unix(unix, 0).UTC().Format("15:04 on 2 Jan 2006") + " UTC"
		},
		// A credential id as a form value. base64url because that is what
		// WebAuthn uses everywhere else, and mixing encodings for one
		// identifier is how a lookup silently stops matching.
		"b64": func(b []byte) string {
			return base64.RawURLEncoding.EncodeToString(b)
		},
		"ago": func(unix int64) string { return agoAt(unix, time.Now()) },
		// bytes is a file size as a person reads it: "2.4 MB", not 2411954.
		"bytes": humanBytes,
	}).ParseFS(assets, "assets/*.html")
	if err != nil {
		return nil, fmt.Errorf("admin templates: %w", err)
	}
	return &Server{Policy: p, Tokens: ts, proofs: &dpop.Replays{}, tpl: t, flashKey: newFlashKey()}, nil
}

// fixPart is a run of a fix's note: words, or a command it names.
type fixPart struct {
	Text string
	Code bool
}

// fixWords is a fix as a command and the note that follows it.
type fixWords struct {
	Cmd  string
	Note []fixPart
}

// fixParts splits "aertun auditlog anchor  # or `auditlog head --save`"
// into the command and a note of words and commands, the backticks gone.
func fixParts(fix string) fixWords {
	cmd, note, ok := strings.Cut(fix, " # ")
	if !ok {
		if !strings.Contains(fix, "`") {
			return fixWords{Cmd: fix}
		}
		// Words that name a command: the words as words.
		cmd, note = "", fix
	}
	out := fixWords{Cmd: strings.TrimSpace(cmd)}
	for i, seg := range strings.Split(strings.TrimSpace(note), "`") {
		if seg != "" {
			out.Note = append(out.Note, fixPart{Text: seg, Code: i%2 == 1})
		}
	}
	return out
}

// countOf is a count with its noun, for a template whose count may be any
// integer type: "1 advisory", "8 advisories", "0 pages".
func countOf(n any, one, many string) string {
	v := reflect.ValueOf(n)
	var i int64
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i = v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		i = int64(v.Uint())
	default:
		return fmt.Sprint(n) + " " + many
	}
	if i == 1 {
		return "1 " + one
	}
	return strconv.FormatInt(i, 10) + " " + many
}

// errNoCredential means nothing was presented, as distinct from something
// being rejected.
//
// The two used to be one error, and the sign-in screen showed "no token" in a
// red alert box to everybody arriving for the first time — announcing a
// failure to somebody who had not yet done anything. An error message is for
// something that went wrong, and opening a page you are not signed in to is
// not that.
var errNoCredential = errors.New("no token")

// principal is who the current request is acting as.
type principal struct {
	Name string
	// StepUp is why this session must prove its person before anything
	// else; empty when it need not. Bound is where it was issued to. See
	// automations.go.
	StepUp, Bound string
	// Role is the role the *token* carries, which may be narrower than the one
	// the policy grants Name. It was captured here and then used only to print
	// "Signed in as … (role)" in the header — a decorative field that looked
	// like an enforced one.
	Role auth.Role
	// Scope is the subtree the token is confined to, from `token issue --on`.
	// It was not captured at all, so a token issued for /blog reached every
	// screen in the interface.
	Scope string
	// Limits is what the token itself narrows, over and above the role: it may
	// be read-only, or restricted to particular content types or locales.
	//
	// Dropped here for a long time. authenticate() kept the principal's name
	// and the token's role and discarded the rest, so `--read-only` was
	// enforced in internal/api — the one place that reads the token directly —
	// and nowhere else. A read-only token could save a page and publish it
	// through this interface, which is the interface most people use.
	Limits auth.Scope
	// TokenID and Session identify the credential itself, so signing out can
	// revoke the session it was issued for rather than only forgetting it.
	TokenID string
	Session bool
	// Level is the assurance level the request is made at (auth.Token.Level)
	// and Methods how its session was signed in to; Bearer says the
	// credential came in an Authorization header rather than the session
	// cookie a browser holds. Grace is set while one factor is still let
	// through, with the date two become compulsory.
	Level   int
	Methods []string
	Bearer  bool
	Grace   string
	// Proof is the token the request came with, kept for what only it can
	// answer: when, and how, its person last proved themselves.
	Proof auth.Token
}

// firstFactorOnly is what a session signed in with a token alone is told:
// a token is one factor, and a person's every request carries two.
const firstFactorOnly = "You signed in with a token, which is one factor. Confirm it is you with your passkey, " +
	"or sign in again through single sign-on."

// ssoFirstFactorOnly is what a single sign-on is told when the identity
// provider did not say it used more than one factor.
const ssoFirstFactorOnly = "Your organisation's sign-in did not say it used a second factor, so it counts as one. " +
	"Confirm it is you with your passkey."

// mfaEnforced reports whether two factors are compulsory now: from
// MFAFrom, the end of the grace an installation was given when two
// factors became the rule.
func (s *Server) mfaEnforced(now time.Time) bool { return !now.Before(s.MFAFrom) }

// authenticate resolves a request to a principal.
//
// Bearer token only. There is no password form, which removes password storage,
// reset flows, and credential stuffing in one go — and pasting a token is not a
// cognitive function test, which is what WCAG 2.2 3.3.8 is about.
func (s *Server) authenticate(r *http.Request) (principal, error) {
	s.refresh()
	header := r.Header.Get("Authorization")
	raw := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	bearer := raw != ""
	if raw == "" {
		if c, err := r.Cookie("aertun_token"); err == nil {
			raw = c.Value
		}
	}
	if raw == "" {
		return principal{}, errNoCredential
	}
	tok, err := s.Tokens.Authenticate(raw, time.Now())
	// A session waiting to prove its person is let this far, carrying why,
	// and requireAuth sends it nowhere but "Confirm it's you".
	if err != nil && !(errors.Is(err, auth.ErrStepUp) && tok != nil) {
		return principal{}, err
	}
	p := principal{
		Name: tok.Principal, Role: tok.Role, Scope: tok.Resource,
		Limits: tok.Scope, TokenID: tok.ID, Session: tok.IsSession(), StepUp: tok.StepUp,
		Bound: tok.Bound, Level: tok.Level(), Methods: tok.Methods, Bearer: bearer,
		Proof: *tok}
	// Two factors on every request a person makes (SP 800-63B-4 AAL2), not
	// only at the sign-in form: a token pasted into the form, or sent in a
	// header, is one, and the session it makes waits for a passkey as a
	// held session does. Before MFAFrom it is let through, and told when
	// that ends.
	if p.Level < 2 {
		if s.mfaEnforced(time.Now()) {
			if p.StepUp == "" {
				p.StepUp = firstFactorOnly
				if hasMethod(p.Methods, auth.MethodSSOOneFactor) {
					p.StepUp = ssoFirstFactorOnly
				}
			}
		} else {
			p.Grace = s.MFAFrom.UTC().Format("2 January 2006")
		}
	}
	return p, nil
}

// Session is the person signed in to the console that a request carries, for
// a surface mounted beside the console: the authorization server's
// authorization endpoint, which has to know who is approving an agent's ask
// before it shows one.
//
// The console's own rules hold. A request that authenticated with a pasted
// token is refused — the console is for people signed in with two factors,
// and a consent given over a one-factor bearer is a consent whoever lifted
// the token could also give. A session waiting to prove its person is
// refused too, for the same reason requireAuth refuses it everywhere: the
// person has not confirmed they are the one holding the session.
//
// Exported read-only and to no other purpose: this resolves, it never
// authorises. What the person may consent to is the policy's to say, and the
// caller asks its own hook for that.
func (s *Server) Session(r *http.Request) (string, bool) {
	if r.Header.Get("Authorization") != "" {
		return "", false
	}
	p, err := s.authenticate(r)
	if err != nil || !p.Session || p.StepUp != "" {
		return "", false
	}
	return p.Name, true
}

// can checks a permission and writes the refusal itself if there is one.
//
// The refusal says which role was needed. "Forbidden" with no explanation makes
// someone guess or ask an admin for more than they need, which is how access
// creeps upward.
func (s *Server) can(w http.ResponseWriter, r *http.Request, p principal,
	act auth.Action, resource string) bool {

	// The token's own limits first, because they cap the session regardless of
	// what the principal may do in general. A publisher holding a read-only
	// token is, for this request, not a publisher — that is the entire reason
	// to issue one.
	//
	// All of them, through the shared check. This used to consult only
	// Limits — the read-only/type/locale dimensions — and ignore the two the
	// README advertises first: `--role reader` and `--on /path`. The token's
	// role was captured into the principal and used to render a label, which
	// is how it passed for enforcement. The consequence was not subtle: a
	// credential issued `--role reader` to an administrator was refused a
	// publish on the command line and could POST /people/grant here to make
	// anybody an admin, because Evaluate was asked about the person and never
	// about the credential.
	//
	// A permission granted on its own (auth's permission.go) is capped by the
	// credential's path and limits rather than its role, as on the command
	// line, so the decision is made first and then capped: a reader holding
	// approve on one agent uses it through their own session, and an
	// administrator's reader-capped credential still cannot, because their
	// approve comes from the role.
	d := s.Policy.Evaluate(p.Name, act, resource)
	if err := auth.CheckGranted(d, p.Role, p.Scope, p.Limits, act, resource); err != nil {
		s.render(w, r, "message.html", map[string]any{"Status": http.StatusForbidden,
			"Title": "Not permitted", "Principal": p,
			"Heading": "This credential cannot do that",
			"Body":    err.Error(),
		})
		return false
	}
	if d.Allowed {
		return true
	}
	s.render(w, r, "message.html", map[string]any{"Status": http.StatusForbidden,
		"Title": "Not permitted", "Principal": p,
		"Heading": "You cannot do that here",
		"Body":    d.Reason,
	})
	return false
}

// allows is can without an answer written: whether a person, through this
// session, may act on a resource, for deciding what a screen shows.
func (s *Server) allows(p principal, act auth.Action, resource string) bool {
	if s.Policy == nil {
		return true
	}
	d := s.Policy.Evaluate(p.Name, act, resource)
	return d.Allowed && auth.CheckGranted(d, p.Role, p.Scope, p.Limits, act, resource) == nil
}

// Asking the authorisation question about the page, and not about the site.
//
// # What was wrong
//
// The policy supports a binding scoped to part of the site — `--on /blog`,
// which the README describes as enforced, and `--deny` on a path, which the
// people screen renders as a rule. Eight handlers here read a page name out of
// the request and then asked whether the caller could act on "/".
//
// That is wrong in both directions at once, and only one of them is visible.
//
// covers("/blog", "/") is false, so an author granted author on /blog was
// refused everything: the pages list, their own page's notes, a review date on
// a page inside their scope. The editor rendered and every control in it
// answered 403. Somebody narrowed to part of the site could not use the
// browser at all.
//
// And a deny scoped to a path never matched, because the target was always
// "/". A principal holding admin on "/" and denied author on /about was
// refused by the command line and permitted here:
//
//	aertun note add about "…"                  denied author on /about
//	POST /notes/add page=about text=…          200, and the note was written
//
// The browser is the surface where the deny is *displayed*, which makes this
// the worse half: somebody reads the policy on the people screen, sees the
// rule, and believes it.
//
// # The shape of the fix
//
// canPage for the handler that knows the name, canAnywhere for the screen that
// is about to list things and does not know a name yet. A test walks this
// package's source and fails when a handler reads a page name and authorises
// "/", because this is a convention and the convention is what did not hold.

// canAnywhere is the gate for a screen that lists things it has not named yet.
//
// It asks whether the caller may do this anywhere at all, and the screen then
// asks the per-page question for every row it is about to show. Weak on
// purpose: it decides whether the screen opens, not what is on it.
func (s *Server) canAnywhere(w http.ResponseWriter, r *http.Request,
	p principal, act auth.Action) bool {

	if s.Policy == nil {
		return s.can(w, r, p, act, "/")
	}
	// The credential's own limits still apply. Its role cap and its read-only
	// and type dimensions are site-wide by nature — a read-only token is
	// read-only everywhere — so they are asked here in full. Only its path
	// dimension is asked about itself rather than about "/", because a token
	// scoped to /blog failing to cover "/" is the same wrong question this
	// function exists to stop asking.
	within := strings.TrimSpace(p.Scope)
	if within == "" {
		within = "/"
	}
	if s.Policy.Anywhere(p.Name, act) &&
		auth.CheckCredential(p.Role, p.Scope, p.Limits, act, within) == nil {
		return true
	}
	return s.can(w, r, p, act, "/")
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string,
	data map[string]any) {

	// Everything the shell needs, resolved here rather than in each handler.
	//
	// Set in one place because a screen added later cannot forget it. The
	// earlier version required each handler to pass "Nav", and a handler that
	// did not made the template compare a nil against a string — which surfaces
	// as a half-rendered page rather than as a failure, so it is exactly the
	// kind of mistake that ships.
	if _, ok := data["Nav"]; !ok {
		data["Nav"] = ""
	}
	navKey, _ := data["Nav"].(string)

	theme := themeOf(r)
	next, nextLabel := nextTheme(theme)
	data["Theme"] = theme
	data["ThemeNow"] = themeLabel(theme)
	data["ThemeNext"] = next
	data["ThemeNextLabel"] = nextLabel

	// Whether the navigation is showing, and therefore what the control does.
	// Resolved here for the same reason the theme is: a screen added later
	// cannot forget it.
	data["SidebarHidden"] = sidebarHidden(r)

	// Where the preference toggles come back to.
	//
	// Every response here sets Referrer-Policy: no-referrer, so the browser
	// tells the toggle nothing about where it was pressed. The screen has to
	// say so itself, and it says so from here for the same reason as the two
	// above: a screen added later cannot forget it.
	//
	// Passed through safeLocalPath on the way out as well as on the way back
	// in. It is this server's own URL and so it is already local, but a value
	// written into a form is a value somebody can read, edit and post — and
	// the check on return is the one that matters either way.
	data["Here"] = safeLocalPath(r.URL.Path, r.URL.RawQuery)

	// The interface's one script, allowed by a nonce that is this response's
	// alone. It adds what a browser cannot do on its own — the command
	// palette, keyboard shortcuts — and every screen still works without it.
	// A page that set its own policy (the passkey screens, which carry a
	// script of their own) keeps it, and its nonce covers this script too.
	h := w.Header()
	if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src") {
		if n, err := nonce(); err == nil {
			if _, set := data["Nonce"]; !set {
				data["Nonce"] = n
			}
			h.Set("Content-Security-Policy", csp+"; script-src 'nonce-"+n+"'")
		}
	}
	if p, ok := data["Principal"].(principal); ok {
		data["Initial"] = initialOf(p.Name)
		// The page tells the server somebody is there, warns before the
		// end and offers to sign in again in place, only where the end
		// applies (idle.go).
		if p.Session && fromBrowser(r) {
			data["IdleSeconds"] = int(s.idleFor(p.Name).Seconds())
		}
	}

	// The documentation link for the screen being rendered, so the footer link
	// means "help with this" rather than "help".
	//
	// A whole URL rather than an anchor the template concatenates. The manual
	// is published separately now, and a template that builds
	// "/docs#{{.Doc}}" against an external site would have to know the host —
	// which is how a relative link to a page that no longer exists survives a
	// move and 404s quietly on every screen.
	data["Brand"] = brandName
	data["DocURL"] = DocURL(docFor(navKey))
	data["DocsBase"] = DocsBase
	// The mark, from the one place it is defined.
	data["MarkPath"] = MarkPath
	data["MarkFirst"], data["MarkSecond"] = MarkFirst, MarkSecond

	// The navigation itself, filtered to what this person may use and sorted
	// into the order they chose.
	if p, ok := data["Principal"].(principal); ok {
		data["Nav"] = navKey
		data["NavGroups"] = s.navigation(r, p, navKey)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A status other than 200 is passed in rather than written by the
	// handler first: once a status is written the headers are sent, and the
	// policy above, which lets this page's script run, would be lost.
	if st, ok := data["Status"].(int); ok && st != 0 {
		w.WriteHeader(st)
	}
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		// The status is already sent by now, so this can only be logged, not
		// turned into a clean error page.
		fmt.Fprintf(w, "\n<!-- render error: %v -->", err)
	}
}

// securityHeaders applies the same posture as the rest of the project.
//
// The CSP forbids inline script and every external origin. The admin needs no
// script at all, so this is not a restriction anyone has to work around — it is
// a statement that there is nothing to execute, enforced by the browser as well
// as by the architecture.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", adminPolicy("'none'"))
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		// A window this origin opens, or that opens it, shares no handle
		// with the other: no window.opener to navigate, no process to share
		// with a page somebody else controls.
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		// Nothing here is meant to be embedded by another site — not the
		// pages, and not the media, which is behind a sign-in anyway.
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		// Device capabilities this interface never uses, switched off so a
		// page it renders cannot ask for them either. Credentials are left
		// at the default, which is this origin: passkeys need it.
		h.Set("Permissions-Policy",
			"camera=(), microphone=(), geolocation=(), payment=(), usb=(), "+
				"serial=(), hid=()")
		// Not stored, by the browser or anything in between.
		//
		// Five handlers said so and the rest said nothing, so the pages
		// listing people, tokens, audit entries and security events were
		// cacheable — on a shared machine, the back button after signing out
		// showed them. A default here, rather than a line per handler: a
		// screen added later is covered without anybody remembering. The
		// few responses that should be cached — the stylesheet, media
		// addressed by its own hash — set their own value, which replaces
		// this one.
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// adminPolicy is the interface's content security policy, with the one
// directive that differs between responses supplied.
//
// manifest-src is the one directive this needed to become installable. It
// permits a JSON file from this origin and nothing else — no script, no
// fetch, no capability the interface did not already have.
//
// frame-src 'self' is what lets the editor show the real page beside the
// form. The framed document is /preview/NAME, served by this same server
// under this same policy, so nothing inside it can execute either.
//
// frame-ancestors is 'none' everywhere except that document. It used to be
// 'none' there too, beside a comment saying this origin may frame itself —
// which 'none' forbids, so the editor's preview was a grey box in every
// browser that enforces the directive, which is all of them.
//
// media-src 'self' because a preview of a page with a film on it is a
// preview of that page.
//
// connect-src 'self' so the one script can send what a form would, without
// loading the page again: the menu control hides the sidebar at once. It
// reaches nothing a form could not, since form-action is 'self' already,
// and no other origin.
func adminPolicy(frameAncestors string) string {
	return "default-src 'none'; style-src 'self'; img-src 'self' data:; " +
		"font-src 'self'; connect-src 'self'; " +
		"media-src 'self'; manifest-src 'self'; frame-src 'self'; " +
		"form-action 'self'; frame-ancestors " + frameAncestors +
		"; base-uri 'none'"
}

// MaxRequestBody caps a POST. Without a limit a single request can make the
// process allocate until it dies, which needs no credential and no cleverness.
const MaxRequestBody = 2 << 20 // 2 MiB

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			next.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBody)
		next.ServeHTTP(w, r)
	})
}

func sameSiteOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut &&
			r.Method != http.MethodDelete {
			next.ServeHTTP(w, r)
			return
		}
		// The one cross-site POST accepted: an identity provider's page
		// posting a SAML response. It changes nothing unless a signed
		// assertion answers a request this browser made; see samlauth.go.
		if isSAMLACS(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Sec-Fetch-Site is authoritative when the browser sends it.
		//
		// It is set by the browser itself and a page cannot forge it, so
		// "same-origin" is a stronger statement than anything Origin can make
		// — and once it has been made, re-checking Origin can only produce
		// disagreements with a request that is already known to be fine.
		//
		// It did. Signing in from Brave failed with "this request came from
		// another origin" while the same POST from curl succeeded: the
		// browser said same-origin, and then sent an Origin the comparison
		// did not like — privacy-hardened browsers send `null` in situations
		// where a stricter one sends the real value. Both lines of defence
		// were present, and the second one refused what the first had just
		// approved.
		//
		// So Sec-Fetch-Site decides when it is there, and Origin is the
		// fallback for clients that do not send it. Belt and braces, with the
		// braces no longer able to drop the trousers.
		switch r.Header.Get("Sec-Fetch-Site") {
		case "same-origin", "none":
			next.ServeHTTP(w, r)
			return
		case "":
			// Not sent. Fall through to Origin.
		default:
			http.Error(w, "cross-site requests cannot change anything here",
				http.StatusForbidden)
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host {
				// Named, because "another origin" gives somebody staring at a
				// blank page nothing to act on. This is the message an
				// operator behind a proxy that rewrites Host will need.
				http.Error(w, fmt.Sprintf(
					"this request says it came from %q and this server is "+
						"%q. If something in front of this rewrites the Host "+
						"header, it needs to preserve it.",
					origin, r.Host), http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Handler returns the router.
// readOnlyTokens refuses a state-changing request from a credential that says
// it makes none.
//
// In middleware rather than in each handler, and keyed on the method rather
// than the action, because the per-action check inside can() can be — and was —
// reached after a handler has already validated its input. /save answered 400
// "no page name" to a read-only token, which is a handler deciding the request
// is malformed before anything decided the caller may make it at all. Ordering
// like that is not wrong by much, and it is wrong in the direction where the
// next handler somebody writes gets it wrong too.
//
// GET and HEAD pass through; everything else with a read-only token is refused
// here, before a single field is read. can() still carries the finer checks —
// a token limited to some content types or locales needs to know which page is
// being touched, and only the handler knows that.
func (s *Server) readOnlyTokens(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		// The token exchange reads its own bearer token and refuses what a
		// read-only one may not have itself.
		if r.URL.Path == "/token/exchange" {
			next.ServeHTTP(w, r)
			return
		}
		// An unauthenticated request is not this middleware's problem: the
		// handler will refuse it, and answering here would tell an anonymous
		// caller which routes exist.
		p, err := s.authenticate(r)
		if err != nil || !p.Limits.ReadOnly {
			next.ServeHTTP(w, r)
			return
		}
		s.render(w, r, "message.html", map[string]any{"Status": http.StatusForbidden,
			"Title": "Not permitted", "Principal": p,
			"Heading": "This credential cannot change anything",
			"Body": "This token was issued read-only, so it refuses every " +
				"write whatever the role it carries. Use a token without " +
				"--read-only, or ask for one.",
		})
	})
}

// Handler is the console: the screens, the sign-in that guards them, and
// the endpoints identity providers and collectors call.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHome)

	// Signing in, and the person's own account.
	mux.HandleFunc("/signin", s.handleSignIn)
	mux.HandleFunc("/signout", s.handleSignOut)
	mux.HandleFunc("/signin/verify", s.handleStepUp)
	mux.HandleFunc("/signin/verify/report", s.handleStepUpReport)
	mux.HandleFunc("/signin/passkey", s.handlePasskeySignIn)
	mux.HandleFunc("/signin/passkey/challenge", s.handlePasskeySignInChallenge)
	mux.HandleFunc("/signin/passkey/verify", s.handlePasskeyVerify)
	mux.HandleFunc("/signin/oidc", s.handleOIDCStart)
	mux.HandleFunc("/signin/saml/", s.handleSAMLStart)
	mux.HandleFunc("/signin/sso", s.handleSSODiscover)
	mux.HandleFunc("/auth/callback", s.handleOIDCCallback)
	mux.HandleFunc("/saml/", s.handleSAML)
	mux.HandleFunc("/enrol/", s.handleEnrol)
	mux.HandleFunc("/passkeys", s.handlePasskeys)
	mux.HandleFunc("/passkeys/challenge", s.handlePasskeyChallenge)
	mux.HandleFunc("/passkeys/register", s.handlePasskeyRegister)
	mux.HandleFunc("/passkeys/remove", s.handlePasskeyRemove)
	mux.HandleFunc("/profile", s.handleProfile)
	mux.HandleFunc("/profile/session/end", s.handleSessionEnd)
	mux.HandleFunc("/session/alive", s.handleAlive)
	mux.HandleFunc("/token/exchange", s.handleTokenExchange)

	// The first screen, and what waits for a decision.
	mux.HandleFunc("/today", s.handleToday)
	mux.HandleFunc("/start", s.handleStart)
	mux.HandleFunc("/start/done", s.handleStartDone)
	mux.HandleFunc("/approvals", s.handleApprovals)
	mux.HandleFunc("/find", s.handleFind)

	// Collection and what was collected.
	mux.HandleFunc("/security/events", s.handleEventsScreen)
	mux.HandleFunc("/security/hunt", s.handleHunt)
	mux.HandleFunc("/security/agents", s.handleAgents)
	mux.HandleFunc("/security/agents/", s.handleAgent)
	mux.HandleFunc("/security/egress", s.handleEgress)
	mux.HandleFunc("/security/feeds", s.handleFeeds)
	mux.HandleFunc("/security/feeds/act", s.handleFeedsAct)
	mux.HandleFunc("/security/entity/", s.handleEntity)

	// Detection, findings and response.
	mux.HandleFunc("/security/detections", s.handleDetections)
	mux.HandleFunc("/security/detections/act", s.handleDetectionsAct)
	mux.HandleFunc("/findings", s.handleFindings)
	mux.HandleFunc("/findings/", s.handleFinding)
	mux.HandleFunc("/findings/decide", s.handleFindingDecide)
	mux.HandleFunc("/security/risk", s.handleRisk)
	mux.HandleFunc("/proving/proofs", s.handleProofs)
	mux.HandleFunc("/proving/proofs/keep", s.handleProofKeep)
	mux.HandleFunc("/proving/proofs/", s.handleProof)
	mux.HandleFunc("/proving/claims", s.handleClaims)
	mux.HandleFunc("/proving/adjudication", s.handleAdjudication)
	mux.HandleFunc("/proving/adjudication/judge", s.handleAdjudicationJudge)
	mux.HandleFunc("/proving/adjudication/", s.handleAdjudicationItem)
	mux.HandleFunc("/security/indicators", s.handleIndicators)
	mux.HandleFunc("/security/indicators/act", s.handleIndicatorsAct)
	mux.HandleFunc("/security/cases", s.handleCases)
	mux.HandleFunc("/security/cases/act", s.handleCasesAct)
	mux.HandleFunc("/security/case/", s.handleCase)
	mux.HandleFunc("/security/automations", s.handleAutomations)
	mux.HandleFunc("/security/automations/rule", s.handleAutomationRule)
	mux.HandleFunc("/security/automations/act", s.handleAutomationsAct)
	mux.HandleFunc("/security/signins", s.handleSignIns)
	mux.HandleFunc("/security/signins/act", s.handleSignInsAct)
	mux.HandleFunc("/security/signins/unlock", s.handleSignInsUnlock)

	// Vulnerabilities, and the estate's people and machines.
	mux.HandleFunc("/security/vulns", s.handleVulns)
	mux.HandleFunc("/security/vulns/act", s.handleVulnsAct)
	mux.HandleFunc("/security/vuln/", s.handleVuln)
	mux.HandleFunc("/workforce", s.handleWorkforce)
	mux.HandleFunc("/workforce/person/", s.handleWorkforcePerson)
	mux.HandleFunc("/workforce/devices", s.handleWorkforceDevices)
	mux.HandleFunc("/workforce/sync", s.handleWorkforceSync)
	mux.HandleFunc("/workforce/reminders", s.handleReminders)
	mux.HandleFunc("/workforce/reminders/act", s.handleRemindersAct)

	// Administration: people, sign-in providers, settings, the audit log.
	mux.HandleFunc("/people", s.handlePeople)
	mux.HandleFunc("/people/grant", s.handlePeopleGrant)
	mux.HandleFunc("/people/revoke", s.handlePeopleRevoke)
	mux.HandleFunc("/people/enrol", s.handlePeopleEnrol)
	mux.HandleFunc("/people/enrol/revoke", s.handlePeopleEnrolRevoke)
	mux.HandleFunc("/people/pending", s.handlePeoplePending)
	mux.HandleFunc("/sessions/revoke", s.handleSessionRevoke)
	mux.HandleFunc("/sso", s.handleSSO)
	mux.HandleFunc("/sso/act", s.handleSSOAct)
	mux.HandleFunc("/provisioning", s.handleProvisioning)
	mux.HandleFunc("/provisioning/act", s.handleProvisioningAct)
	mux.HandleFunc("/settings", s.handleSettings)
	mux.HandleFunc("/settings/save", s.handleSettingSave)
	mux.HandleFunc("/logs", s.handleLogs)

	// The interface's own furniture.
	mux.HandleFunc("/theme", s.handleTheme)
	mux.HandleFunc("/sidebar", s.handleSidebar)
	mux.HandleFunc("/nav/order", s.handleNavOrder)
	mux.HandleFunc("/style.css", s.handleCSS)
	mux.HandleFunc("/admin.js", s.handleJS)
	mux.HandleFunc("/fonts/aertun-ui.woff2", s.handleFont)
	mux.HandleFunc("/icon.svg", s.handleIcon)
	// The live stream over the audit log (live.go). A page resource with the
	// rest of the furniture, not an agent API: it is opened by the console's
	// own script on the console's own session, and the CSP's connect-src
	// 'self' already permits it.
	mux.HandleFunc("/live", s.handleLive)

	// Endpoints other systems call, each with its own authentication: the
	// identity provider's provisioning, and events pushed here.
	if s.SCIM != nil && s.SCIM.Handler != nil {
		mux.Handle("/scim/v2/", s.SCIM.Handler)
	}
	if s.Inbound != nil {
		mux.Handle("/feeds/", s.Inbound)
	}
	return securityHeaders(s.signedFlash(sameSiteOnly(limitBody(s.readOnlyTokens(mux)))))
}

// handleHome sends a signed-in person to their first screen.
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	http.Redirect(w, r, "/today", http.StatusSeeOther)
}

// handleIcon is the mark, for the browser's tab.
func (s *Server) handleIcon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(MarkSVG(MarkFirstColour)))
}

// handleSignIn exchanges a pasted token for a session cookie.
//
// A POST, because the previous version was a GET form: submitting put the token
// in the URL, and from there into browser history, the server's access log, and
// the Referer header of every outbound link. A credential in a URL is a
// credential in several places nobody thinks to clear.
//
// Every refusal is a redirect back to the form, never a page rendered in
// answer to the POST. The page answering a POST is the page a browser offers
// to resubmit: somebody who pasted the right token while throttled got the
// "too many attempts" page, pressed reload once the wait was over, and was
// signed in by a token they had not entered this time — the browser still
// held it. It also sits in session history for back and forward to replay.
// Post/Redirect/Get leaves nothing behind to send again.
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.signInForm(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// The same limiter every other credential check goes through.
	//
	// This form did not. requireAuth throttles a token presented as a cookie,
	// and the identical guess sent through the sign-in box was free: measured
	// against the running server, forty wrong tokens through here returned
	// forty 401s and never once a 429, while two through the cookie path were
	// enough to start refusing.
	//
	// Worse than the missing limit is the missing count. Failures here never
	// reached Throttle.Fail, so they did not contribute to the per-source
	// counter that protects every other surface, and they never crossed the
	// threshold that fires OnAuthFailure — so a sustained attempt against the
	// one door built for people raised no alert at all.
	sub := throttle.Subject{Source: sourceOf(r)}
	if s.Throttle != nil {
		if d := s.Throttle.Check(sub); !d.Allowed {
			// Not looked at, so not counted: the token in this request is
			// neither a failure nor a success.
			signInAgain(w, r, "throttled")
			return
		}
	}

	raw := strings.TrimSpace(r.FormValue("token"))
	tok, err := s.Tokens.Authenticate(raw, time.Now())
	if err != nil {
		if s.Throttle != nil {
			d, alert := s.Throttle.Fail(sub)
			if alert && s.OnAuthFailure != nil {
				s.OnAuthFailure(sub.Source, d.Failures)
			}
		}
		why := "refused"
		if !strings.HasPrefix(raw, auth.TokenPrefix) {
			why = "format"
		}
		signInAgain(w, r, why)
		return
	}

	// Somebody signed in, and the log says so.
	//
	// It did not. OnSignIn exists and is assigned only inside the OIDC block
	// in cmd/aertun, so on the ordinary deployment — a token, or a passkey,
	// and no identity provider — the log held content changes with no record
	// of anybody ever signing in at all. AU-2 asks for the session, not only
	// for what was done inside it.
	//
	// The success, not every failure. A failure record is written by whoever
	// is failing, and an unauthenticated caller who can make the log grow is
	// a way to bury the entries that matter; the throttle's alert above is the
	// bounded version of the same signal.
	// The cookie holds a session, never the token that was pasted.
	//
	// It held the token itself, which is somebody's long-lived credential —
	// thirty days by default. A cookie is the credential most likely to be
	// copied (a proxy log, a shared machine, a browser profile synced
	// somewhere) and signing out could not help: revoking would destroy the
	// token the person signs in with. An eight-hour session exchanged from it
	// bounds the first and lets signing out revoke the second. A pasted
	// session is already short-lived and cannot be exchanged again, so it is
	// used as it is.
	// An organisation that requires single sign-on gets it: a pasted token
	// is the one way round the identity provider's MFA and offboarding.
	// The API still takes tokens; this is the browser's front door.
	if s.ssoRequired(tok.Principal) != "" {
		s.audit("session.refused", "/", map[string]string{"by": tok.Principal,
			"credential": tok.ID, "why": "single sign-on is required"})
		signInAgain(w, r, "sso")
		return
	}
	cookie, cookieTok := raw, *tok
	if !tok.IsSession() {
		secret, sess, xerr := s.Tokens.Exchange(raw, auth.RoleNone, "",
			s.sessionMax(), time.Now())
		if xerr != nil {
			signInAgain(w, r, "refused")
			return
		}
		if s.SaveTokens != nil {
			if serr := s.SaveTokens(s.Tokens); serr != nil {
				http.Error(w, "the session could not be stored: "+serr.Error(),
					http.StatusInternalServerError)
				return
			}
		}
		cookie, cookieTok = secret, sess
	}
	maxAge := int(time.Until(time.Unix(cookieTok.ExpiresAt, 0)).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}

	s.audit("session.start", "/", map[string]string{
		"by": tok.Principal, "credential": tok.ID, "session": cookieTok.ID,
		"how": "token",
	})
	stepUp, serr := s.signInCheck(r, tok.Principal, cookieTok.ID, "token", false)
	if serr != nil {
		signInAgain(w, r, "unchecked")
		return
	}
	s.signInDone(r, cookieTok.ID)

	// Secure over TLS, or where the deployment says something in front of it
	// is terminating TLS. Not unconditionally: a Secure cookie is refused on a
	// loopback deployment and nobody can sign in at all — which is how a
	// security attribute gets removed permanently by whoever is trying to get
	// their work done.
	//
	// This was `r.TLS != nil`, which answers the question for the deployment
	// that terminates TLS here and gets it wrong for the one that puts a proxy
	// in front — where the browser speaks HTTPS, this process sees plain HTTP,
	// and the cookie holding the API token went out without Secure. See
	// secureCookie, and admin.behind_tls_proxy, which is how a deployment says
	// which it is.
	http.SetCookie(w, &http.Cookie{
		Name: "aertun_token", Value: cookie, Path: "/",
		HttpOnly: true,                    // unreadable by script; there is none, but the header outlives that
		SameSite: http.SameSiteStrictMode, // the primary CSRF defence
		Secure:   r.TLS != nil || s.behindTLSProxy(),
		MaxAge:   maxAge,
	})
	if stepUp {
		http.Redirect(w, r, "/signin/verify", http.StatusSeeOther)
		return
	}
	// Somebody signing in for the first time lands on the getting started
	// screen instead of the page list.
	//
	// Here rather than on "/", which was the first attempt and was wrong: it
	// made the landing page answer differently depending on a cookie, so a
	// bookmark, a link somebody shared and every script that fetches the root
	// got a redirect instead of the thing they asked for. Signing in is the
	// moment this belongs to — it is the one request that is unambiguously a
	// person arriving.
	if !startDismissed(r) {
		http.Redirect(w, r, "/start", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, startPath(r), http.StatusSeeOther)
}

// signInReasons is every message the sign-in form will show from its address.
//
// A closed list, keyed by a short code. The code arrives in a query string
// anybody can write, so it selects a sentence rather than supplying one — a
// sign-in page that printed whatever the link said would be a phishing page
// with this site's name on it.
//
// "refused" covers a token that does not exist and one that expired or was
// revoked, deliberately: the API answers both the same way, because telling
// them apart is how an enumeration oracle gets built by accident.
var signInReasons = map[string]string{
	"format": "That is not an Aertun token. They start with " +
		auth.TokenPrefix + " — check the whole of it was pasted.",
	"reported": "Thank you. That session is ended, and your security team " +
		"will look at it. If your token or passkey may have been taken, tell " +
		"them which.",
	"unchecked": "This sign-in has to be confirmed, and that could not be " +
		"recorded, so it was refused. Try again; if it keeps happening, an " +
		"administrator can look at the audit log for session.stepup-unrecorded.",
	"refused": "That token was not accepted. It may be mistyped, expired " +
		"or revoked; an administrator can issue a new one with aertun " +
		"token issue.",
	"sso": "Your organisation requires signing in through its identity " +
		"provider, so a token or a passkey is not accepted here for your " +
		"account. Use your organisation's button above.",
	"nosso": "No organisation sign-in is set up for that address. Sign in " +
		"with a token or a passkey instead, or ask an administrator.",
	"idle": "You were signed out because nobody had used the console for a " +
		"while, as your organisation requires. Sign in again to carry on.",
}

// signInAgain sends the browser back to the form with a reason code.
func signInAgain(w http.ResponseWriter, r *http.Request, why string) {
	http.Redirect(w, r, "/signin?e="+url.QueryEscape(why),
		http.StatusSeeOther)
}

// signInForm renders the form, saying why somebody is back at it.
//
// Whether they are throttled is read from the limiter rather than from the
// address: the code in the query string says what happened to the last
// attempt, and the limiter says what will happen to the next one. The second
// is the one worth a 429.
func (s *Server) signInForm(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Title": "Sign in", "OIDC": s.OIDC != nil,
		"OIDCLabel": s.oidcLabel(), "SSO": s.ssoChoices()}
	if msg, ok := signInReasons[r.URL.Query().Get("e")]; ok {
		data["Error"] = msg
	}
	if s.Throttle != nil {
		sub := throttle.Subject{Source: sourceOf(r)}
		if d := s.Throttle.Check(sub); !d.Allowed {
			secs := int(math.Ceil(d.RetryAfter.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			data["Title"] = "Too many attempts"
			data["Error"] = "Too many attempts from this address. " + d.Why
			data["Status"] = http.StatusTooManyRequests
		}
	}
	s.render(w, r, "signin.html", data)
}

func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	// A session is revoked, not just forgotten.
	//
	// This cleared the cookie and left the credential alive. The OIDC and
	// passkey paths mint a server-side session token that lasts eight hours,
	// so somebody who signed in through an identity provider, pressed Sign
	// out, and walked away had a working credential for the rest of the
	// working day — in a proxy log, in a shared machine's memory, in whatever
	// copied the Authorization header. Signing out is the one moment a person
	// tells you they are finished with a credential, and it was the moment
	// this did the least.
	//
	// Only a session. A long-lived token presented as a cookie is somebody's
	// own credential, used deliberately, and revoking it because they closed
	// a tab would destroy the thing they signed in with.
	if p, err := s.authenticate(r); err == nil && p.TokenID != "" && p.Session {
		if _, err := s.Tokens.Revoke(p.TokenID); err == nil {
			if serr := s.save(); serr == nil {
				s.audit("session.end", "/", map[string]string{"by": p.Name})
			}
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: "aertun_token", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || s.behindTLSProxy(),
	})
	http.Redirect(w, r, "/signin", http.StatusSeeOther)
}

func (s *Server) handleCSS(w http.ResponseWriter, r *http.Request) {
	b, err := assets.ReadFile("assets/style.css")
	if err != nil {
		http.Error(w, "missing stylesheet", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(b)
}

// handleFont serves the interface's typeface. See assets/fonts/README.md.
// Immutable: a new version of the font is a new file name.
func (s *Server) handleFont(w http.ResponseWriter, r *http.Request) {
	b, err := assets.ReadFile("assets/fonts/aertun-ui.woff2")
	if err != nil {
		http.Error(w, "missing font", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "font/woff2")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(b)
}

// handleJS serves the interface's one script. See assets/admin.js.
func (s *Server) handleJS(w http.ResponseWriter, r *http.Request) {
	b, err := assets.ReadFile("assets/admin.js")
	if err != nil {
		http.Error(w, "missing script", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(b)
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) (principal, bool) {
	// Throttled before the credential is looked at, so that a refused attempt
	// costs nothing to check and, more importantly, so the time taken to
	// answer does not depend on whether the presented token exists.
	// The throttle blocks failures, not successes: only the source is known
	// before authentication, so refusing on its history alone locks out
	// everyone behind one address. A throttled request is still
	// authenticated and a valid credential is let through.
	//
	// The credentials are re-read before deciding anything: the console and
	// the command line hold the same file, and a credential revoked by one
	// has to stop working in the other without a restart. The hook stats the
	// file and reloads only when it has changed.
	if s.ReloadTokens != nil {
		s.ReloadTokens()
	}

	sub := throttle.Subject{Source: sourceOf(r)}
	throttled := false
	var tdec throttle.Decision
	if s.Throttle != nil {
		if tdec = s.Throttle.Check(sub); !tdec.Allowed {
			throttled = true
		}
	}

	p, err := s.authenticate(r)
	if err != nil {
		if throttled {
			s.tooManyAttempts(w, r, tdec)
			return principal{}, false
		}
		// Only a credential that was presented and refused is a failure.
		// A request with none guessed nothing — and every browser makes one
		// on the sign-in page, asking for /favicon.ico, which lands here.
		// Counted, five colleagues signing in behind one office address
		// were enough to throttle everybody there.
		if s.Throttle != nil && !errors.Is(err, errNoCredential) {
			d, alert := s.Throttle.Fail(sub)
			if alert && s.OnAuthFailure != nil {
				s.OnAuthFailure(sub.Source, d.Failures)
			}
			if !d.Allowed {
				s.tooManyAttempts(w, r, d)
				return principal{}, false
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		data := map[string]any{"Title": "Sign in", "OIDC": s.OIDC != nil,
			"OIDCLabel": s.oidcLabel(), "SSO": s.ssoChoices()}
		if !errors.Is(err, errNoCredential) {
			data["Error"] = err.Error()
		}
		s.render(w, r, "signin.html", data)
		return principal{}, false
	}
	if s.Throttle != nil {
		// The principal, not the address: see the note in the API middleware.
		s.Throttle.Succeed(throttle.Subject{Principal: p.Name})
	}
	// A browser session nobody has used for session.idle ends here.
	if s.idleOver(w, r, p) {
		return principal{}, false
	}
	// A session used from somewhere other than where it was issued may be
	// a stolen one; the rules decide, and may step it up there and then.
	if p.Session && p.Bound != "" && p.StepUp == "" {
		if reason := s.sessionMoved(r, p); reason != "" {
			p.StepUp = reason
		}
	}
	// A credential sent in a header is a program's, and a program is not a
	// person who can confirm anything: refused here outright rather than
	// sent to a page it cannot use.
	if p.Bearer && p.Level < 2 && s.mfaEnforced(time.Now()) {
		http.Error(w, "the console is for people signed in with two factors, and a token is one. "+
			"Programs use the command line on this machine, the API or the agent interface",
			http.StatusUnauthorized)
		return principal{}, false
	}
	// An organisation that requires single sign-on has it on every request,
	// not only at the sign-in form: a session that did not come through the
	// identity provider is refused, whichever way it was made.
	if why := s.ssoRequired(p.Name); why != "" && !hasMethod(p.Methods, auth.MethodSSO) &&
		!hasMethod(p.Methods, auth.MethodSSOOneFactor) {
		s.audit("session.refused", "/", map[string]string{"by": p.Name, "session": p.TokenID,
			"why": "single sign-on is required"})
		s.clearCookie(w, r, "aertun_token")
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "signin.html", map[string]any{"Title": "Sign in", "OIDC": s.OIDC != nil,
			"OIDCLabel": s.oidcLabel(), "SSO": s.ssoChoices(),
			"Error": "Your organisation requires signing in through " + why + "."})
		return principal{}, false
	}
	// A session waiting to prove its person goes nowhere else first.
	if p.StepUp != "" && !stepUpOpen(r.URL.Path) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			http.Redirect(w, r, "/signin/verify", http.StatusSeeOther)
		} else {
			http.Error(w, "confirm it is you first: /signin/verify", http.StatusForbidden)
		}
		return principal{}, false
	}
	return p, true
}

func hasMethod(methods []string, m string) bool {
	for _, x := range methods {
		if x == m {
			return true
		}
	}
	return false
}

// tooManyAttempts answers a throttled request.
//
// 429 with Retry-After rather than a delay held open on the server. Sleeping
// here would let an attacker exhaust this process's own handlers by failing
// authentication in parallel, which turns the control into the outage.
func (s *Server) tooManyAttempts(w http.ResponseWriter, r *http.Request, d throttle.Decision) {
	secs := int(d.RetryAfter.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	s.render(w, r, "signin.html", map[string]any{"Status": http.StatusTooManyRequests,
		"Title": "Too many attempts", "Error": d.Why,
	})
}

// sourceOf is the address an attempt came from.
//
// RemoteAddr only. A forwarded header is set by whatever is in front, and a
// throttle keyed on a value the client controls is a throttle the client
// switches off by varying it. An operator running behind a proxy wants the
// proxy to do this — it is the thing that can see the real address.
func sourceOf(r *http.Request) string { return clientip.SourceFrom(r) }

// agoAt is a moment as how long before now: "just now", "1 minute ago",
// "3 days ago"; zero is never.
func agoAt(unix int64, now time.Time) string {
	if unix == 0 {
		return "never"
	}
	d := now.Sub(time.Unix(unix, 0))
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return counted(int(d.Minutes()), "minute", "minutes") + " ago"
	case d < 24*time.Hour:
		return counted(int(d.Hours()), "hour", "hours") + " ago"
	default:
		return counted(int(d.Hours()/24), "day", "days") + " ago"
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// initialOf is what the account button shows: the first letter of a name,
// in capitals.
func initialOf(name string) string {
	for _, r := range name {
		return strings.ToUpper(string(r))
	}
	return "?"
}

// ranAgo is when a scan ran, as a person says it: "just now", "5 min ago".
// The report keeps the exact time; the screen does not need it.
func ranAgo(at string) string {
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return at
	}
	return agoText(time.Since(t))
}

// landing is where somebody with no pages to read starts: their first
// screen, passing over the audit log, which is evidence to consult rather
// than where a day's work begins.
func landing(ds []destination) string {
	for _, d := range ds {
		if d.Key != "logs" && d.Key != "today" && d.Path != "/" {
			return d.Path
		}
	}
	for _, d := range ds {
		if d.Path != "/" {
			return d.Path
		}
	}
	return ""
}
