// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/agentreg"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/macaroon"
)

// Who is running this, and did anyone check?
//
// The audit log shipped before this could record any name the caller fancied,
// because the principal came from $USER. `USER=ceo aertun publish` wrote a
// distinct, plausible principal into a tamper-evident chain — integrity
// without authenticity, which is the worse of the two failures because the
// record looks authoritative.
//
// A caller is now resolved from a token where one is presented, and recorded as
// unverified where none is. The unverified case is deliberately not an error:
// a single-user store with nobody granted anything has nothing to enforce, and
// a tool that demands credentials before it will do anything is a tool people
// route around. What it must never do is describe an unproven name as though it
// were established.

// Caller is the resolved identity of whoever is running the command.
type Caller struct {
	Name string
	// Role and Scope are the token's own limits, which cap what this session
	// may do regardless of what the principal is permitted in general.
	Role  auth.Role
	Scope string
	// Limits is the rest of what the token narrows: read-only, and any
	// restriction to particular content types or locales.
	//
	// This was dropped on the floor. The Caller kept the token's role and its
	// resource path and threw the Scope struct away, so `--read-only` was
	// enforced on the content API — the one surface that reads the token
	// directly — and nowhere else. A read-only token could write a page and
	// publish it from the command line or the browser.
	Limits   auth.Scope
	Kind     audit.Kind
	Verified bool
	// Why explains an unverified caller, for the message a refusal prints.
	Why string
	// Bound is whether the token was bound to a key and proved by it, and
	// Life how long the token was issued to last: together, how much a copy
	// of it would be worth to somebody else.
	Bound bool
	Life  time.Duration
	// Model is what an AI caller's acts are recorded as having been decided
	// by: the app at the agent interface (mcp-client), which does not say
	// which model it runs, or an agent acting under its own identity.
	// Empty for a person or a service.
	Model string
	// Agent is the registered agent this token was issued to: the name
	// after the "agent:" prefix of the token's own name (agentreg.Bind).
	// Empty for a person, a plain service credential and the command line.
	//
	// A naming convention, and as weak as the kind heuristic below, said
	// out loud here as there: the token's name is a claim about who it was
	// issued to, not a proof. What the claim buys is the opposite of
	// authority — a caller carrying an agent name is refused by every gate
	// until a registry entry says it is somebody (authorise, below), so
	// minting an agent:-prefixed token grants nothing by itself.
	Agent string
	// Run is the run a credential was minted for, when its name carries
	// one: "agent:watcher/run-42" is agent watcher, run run-42. The run
	// rides the name because the name is the one part of a credential
	// every surface already reads — the token store, the kill switch's
	// revocation sweep, `token list` — so a run-bound credential is
	// recognisable as one everywhere, including where its caveat payload
	// is not checked (those surfaces refuse it; the tool gate checks it).
	Run string
	// RunToken is the caveat-bound form of the token this caller
	// presented, when it was one (internal/macaroon): the whole string,
	// carried unchanged so the one gate that verifies caveats — the agent
	// interface's tool gate — can check the chain against the store's run
	// key. Every other surface ignores it: there, a run token is an
	// ordinary scoped credential, bounded by its role, its resource, its
	// scope and its expiry like any other, and the mint narrows those
	// coarse bounds to match the caveats so the two never disagree.
	RunToken string
	// Proof is the token this caller presented, for what only it can
	// answer: when, and how, its person last proved themselves. Zero for a
	// caller who presented none.
	Proof auth.Token
}

// tokenFile is preferred over the environment.
//
// The research reason, not a stylistic one: every process a user starts
// inherits their environment, so a token in AERTUN_TOKEN is readable by any
// subprocess — including an agent this CLI is designed to be driven by. A file
// at 0600 is read by what opens it deliberately.
func tokenFile() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".aertun", "token")
	}
	return ""
}

// findToken looks in the three places, most deliberate first.
func findToken(explicit string) (string, string) {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit), "--token"
	}
	if p := tokenFile(); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			if t := strings.TrimSpace(string(b)); t != "" {
				return t, p
			}
		}
	}
	if t := strings.TrimSpace(os.Getenv("AERTUN_TOKEN")); t != "" {
		return t, "AERTUN_TOKEN"
	}
	return "", ""
}

// resolveCaller identifies whoever is running the command.
//
// Never returns an error for a missing token. It returns an unverified caller
// and lets the action decide whether that is good enough, which keeps the
// decision where the consequences are.
func resolveCaller(root, explicitToken string) *Caller {
	unverified := func(why string) *Caller {
		return &Caller{
			Name: osUser(), Kind: audit.KindHuman, Verified: false, Why: why,
		}
	}

	secret, from := findToken(explicitToken)
	if secret == "" {
		return unverified("no token was presented")
	}
	// A run token arrives as one string in two halves — credential, then a
	// caveat payload (internal/macaroon) — and the store authenticates the
	// credential half alone, because that is what it holds the hash of.
	// Splitting here, before authentication, is what lets the two halves
	// keep their separate jobs: the store decides the bearer without
	// knowing caveats exist, and the caveat gate — not the store — refuses
	// a payload that does not verify. The whole string is kept for the
	// carry, so what the gate checks is what was presented.
	presented := secret
	isRun := false
	if s, ok := macaroon.Split(secret); ok {
		secret, isRun = s, true
	}
	toks, err := loadTokens(root)
	if err != nil {
		return unverified(fmt.Sprintf("the token store could not be read: %v", err))
	}
	tok, err := toks.Authenticate(secret, time.Now())
	if err != nil {
		// A bad token is worse than none: somebody tried. It is still not an
		// identity, so it is still unverified, and the reason says what happened.
		//
		// Named by where it came from: the file is read before the
		// environment, so somebody who set AERTUN_TOKEN and still has an old
		// file is told which one was tried, instead of hunting for why a
		// token they just issued is "no such token".
		why := fmt.Sprintf("the token from %s was rejected: %v", from, err)
		if from == tokenFile() && strings.TrimSpace(os.Getenv("AERTUN_TOKEN")) != "" {
			why += "; AERTUN_TOKEN is set too, and the file is read first"
		}
		return unverified(why)
	}

	// Using a token records that it was used, which is what makes `token stale`
	// able to find credentials nobody needs any more.
	_ = saveTokens(root, toks)
	c := callerFromToken(tok)
	if isRun {
		c.RunToken = presented
	}
	return c
}

// callerFromToken is the caller a resolved token acts as, shared by the
// command line and the agent interface over HTTP: the same limits, and the
// same honesty about what kind of principal it is, wherever the token was
// presented.
func callerFromToken(tok *auth.Token) *Caller {
	kind := audit.KindService
	if strings.EqualFold(tok.Name, "cli") || strings.Contains(tok.Name, "@") {
		// A weak heuristic, and named as one. Distinguishing a person's own
		// token from a CI credential properly needs the token to say which it
		// is at issue time; until then a service label is the safer default,
		// because over-attributing to a human is the direction that misleads.
		kind = audit.KindHuman
	}
	c := &Caller{
		Name: tok.Principal, Role: tok.Role, Scope: tok.Resource,
		Limits: tok.Scope, Kind: kind, Verified: true, Proof: *tok,
	}
	if name, ok := agentreg.Bind(tok.Name); ok {
		// The agent convention is the one token name that says what kind of
		// principal holds it, which is why it outranks the heuristic above
		// rather than joining it: an agent is an AI principal, and its acts
		// are recorded as its own. The model it runs is not in the registry
		// yet, so the agent's name stands in — an honest placeholder where
		// the audit log insists on not leaving the field empty.
		//
		// A name that carries a run (splitAgentRun) is a run token: the
		// agent is the half before the slash, and the run half is carried
		// beside it. A name with a slash that does not split cleanly claims
		// nothing here — the whole string stands as the claimed agent name,
		// and the registry gate refuses it as somebody it never registered,
		// which is the fail-closed reading of a malformed claim.
		c.Kind = audit.KindAI
		if agent, run, split := splitAgentRun(name); split {
			c.Agent, c.Run, c.Model = agent, run, agent
		} else {
			c.Agent, c.Model = name, name
		}
	}
	return c
}

// splitAgentRun is the agent and the run a token name claims, when it
// claims a run at all: "watcher/run-42" is agent watcher, run run-42.
//
// The run is part of the token's name rather than a field on the stored
// credential because the name is what every surface already reads: the kill
// switch's revocation sweep matches it, `token list` shows it, and the
// store needs no new shape to hold it. Both halves must be shaped like
// registry keys before the claim is honoured — anything else is returned
// unsplit and refused by the registry gate as an agent nobody registered.
func splitAgentRun(bound string) (agent, run string, ok bool) {
	agent, run, found := strings.Cut(bound, "/")
	if !found || !agentreg.ValidName(agent) || !agentreg.ValidName(run) {
		return "", "", false
	}
	return agent, run, true
}

func osUser() string {
	for _, k := range []string{"USER", "USERNAME", "LOGNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return "unknown-operator"
}

// policyInUse reports whether anybody has been granted anything.
//
// This is what decides whether authorisation is enforced, and it needs no
// configuration: a store where nobody has been granted a role is a single-user
// store with nothing to enforce, and the first `auth grant` turns enforcement
// on. A flag would be one more thing to set wrongly.
//
// The error is the important half, and it used to be discarded. A policy that
// could not be read returned false, which meant "nothing has been granted",
// which meant every command ran unauthenticated. Truncating policy.json — with
// an editor, a crash between write and rename, a half-finished restore, or on
// purpose — turned access control off across the whole store, and the only
// symptom was that everything started working:
//
//	aertun add index=home.json          refused, no token
//	echo 'not json' > policy.json
//	aertun add index=home.json          "draft 995b0d7e386f  1 page(s)"
//
// So an unreadable policy is now treated as a policy in force that cannot be
// evaluated, and the answer to every question is no. Absent still means
// unconfigured — that is a store nobody has set up, and it is the case the
// zero-configuration design is for — but present-and-broken is the state where
// refusing is the only safe answer.
func policyInUse(root string) (bool, error) {
	p, err := loadPolicy(root)
	if err != nil {
		return true, fmt.Errorf(
			"this store has a policy that cannot be read, so no request can be "+
				"authorised: %w\n  refusing rather than running unauthenticated; "+
				"repair or remove %s", err, policyPath(root))
	}
	return len(p.Bindings) > 0, nil
}

// authorise checks a caller against the policy for privileged actions.
//
// Returns nil when the action may proceed. The refusal explains which of the
// two things was missing — an identity or a permission — because they need
// different fixes and "forbidden" tells nobody which.
func authorise(root string, c *Caller, action auth.Action, resource string) error {
	// A caller issued to a registered agent answers to its registry entry
	// before the policy is consulted, and whatever the policy says.
	//
	// Two orders were possible and this is not the cosmetic one. After the
	// policy check, a store where nobody holds a binding — the single-user
	// bootstrap, where authorise answers yes to everybody — would have
	// answered yes to an agent: token too, because the short-circuit
	// returns before any gate runs. An agent's authority is its registry
	// row, not the policy's silence, and a store with no policy and no
	// registry is a store where an agent: token names nobody. The registry
	// check runs first so that never depends on somebody having configured
	// anything else (agentGate, in mcpsecurity.go).
	if c.Agent != "" {
		if err := agentGate(root, c); err != nil {
			return err
		}
	}
	inUse, err := policyInUse(root)
	if err != nil {
		return err
	}
	if !inUse {
		return nil // nothing has been granted; there is nothing to enforce
	}
	if !c.Verified {
		return fmt.Errorf(
			"this store has access control configured, so %s needs a verified "+
				"identity (%s).\nPresent one with --token, %s, or AERTUN_TOKEN",
			action, c.Why, tokenFile())
	}
	p, err := loadPolicy(root)
	if err != nil {
		return err
	}
	d := p.Evaluate(c.Name, action, resource)
	if !d.Allowed {
		return fmt.Errorf("%s", d.Reason)
	}

	// The token's own limits, checked second and separately.
	//
	// This was missing, and its absence made scoped tokens decorative: a
	// read-only token issued for CI could publish, because the *person* it acts
	// as is a publisher and only the policy was consulted. Issue-time checking
	// stops somebody minting more authority than they hold; this is what makes
	// a narrow token actually narrow, which is the entire reason to issue one.
	//
	// The three checks that used to be written out here — role cap, path
	// scope, read-only — now live in auth.CheckCredential, because the browser
	// interface and the content API were each doing a different subset of the
	// same three and one of the gaps was a privilege escalation. This surface
	// had them all; being right is not the same as being the only one right.
	return auth.CheckGranted(d, c.Role, c.Scope, c.Limits, action, resource)
}

// auditRecord builds a record carrying whatever was actually established.
func (c *Caller) auditRecord(action, resource string, outcome audit.Outcome,
	detail map[string]string) audit.Record {

	if detail == nil {
		detail = map[string]string{}
	}
	if !c.Verified {
		// Written into the record rather than left to be inferred from a false
		// flag, so a reader scanning entries sees it without checking a field.
		detail["identity"] = "unverified: " + c.Why
	}
	return audit.Record{
		Action: action, Resource: resource, Outcome: outcome,
		Principal: c.Name, Kind: c.Kind, Model: c.Model, Verified: c.Verified, Detail: detail,
	}
}

// authoriseUnder is authorise for anywhere inside an area: whether the
// caller may act on the area or on something in it. What it is used for
// checks the one resource it then touches.
func authoriseUnder(root string, c *Caller, action auth.Action, area string) error {
	err := authorise(root, c, action, area)
	if err == nil {
		return nil
	}
	// A binding that reaches under the area can rescue a policy refusal,
	// and only a policy refusal. The agent registry's decision is not a
	// judgement about resources, so nothing a principal holds anywhere can
	// un-refuse it — without this, the fallback was an override: an
	// unregistered or disabled agent whose principal happened to be granted
	// under the area was let back in by the very loop meant to widen the
	// check, not to second-guess a different gate.
	if c.Agent != "" {
		if gerr := agentGate(root, c); gerr != nil {
			return gerr
		}
	}
	p, perr := loadPolicy(root)
	if perr == nil && c.Verified && p.AnywhereUnder(c.Name, action, area) {
		return nil
	}
	return err
}
