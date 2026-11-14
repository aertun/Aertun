// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/agentreg"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/dpop"
	"github.com/aertun/aertun/internal/macaroon"
	"github.com/aertun/aertun/internal/oauthas"
	"github.com/aertun/aertun/internal/throttle"
)

// Short-lived and bound credentials for programs.
//
// A bearer token works for whoever holds it. Two things narrow that. A
// program exchanges what it holds for a token that lasts minutes (RFC
// 8693), and a token can be bound to a key, so it works only with a fresh
// proof made by that key (RFC 9449, internal/dpop).

const (
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	typeAccessToken    = "urn:ietf:params:oauth:token-type:access_token"
	typeIDToken        = "urn:ietf:params:oauth:token-type:id_token"
	typeJWT            = "urn:ietf:params:oauth:token-type:jwt"
)

// authzToken is the token in a request's Authorization header and the
// scheme it came under.
func authzToken(r *http.Request) (token, scheme string) {
	h := r.Header.Get("Authorization")
	if t, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(t), "Bearer"
	}
	if t, ok := strings.CutPrefix(h, "DPoP "); ok {
		return strings.TrimSpace(t), "DPoP"
	}
	return "", ""
}

// requestURL is the address a request was made to, as a proof names it.
func (s *Server) requestURL(r *http.Request) string { return s.ownOrigin(r) + r.URL.Path }

// proofOf checks the one DPoP proof a request carries, made for it and for
// the token presented, and returns the key's thumbprint.
func (s *Server) proofOf(r *http.Request, token string) (string, error) {
	proofs := r.Header.Values("DPoP")
	if len(proofs) != 1 {
		return "", fmt.Errorf("%w: a request carries exactly one DPoP proof", dpop.ErrProof)
	}
	return dpop.Check(proofs[0], r.Method, s.requestURL(r), token, time.Now(), s.proofs)
}

type exchangeAnswer struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
}

// handleTokenExchange is RFC 8693 token exchange: an Aertun token for a
// narrower one that lasts minutes, or a job's identity token for a token a
// trust says it may have. Bound to a key when the request carries a proof.
func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func(code int, kind, why string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": kind, "error_description": why})
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(http.StatusMethodNotAllowed, "invalid_request", "a token is exchanged with POST")
		return
	}
	if s.ReloadTokens != nil {
		s.ReloadTokens()
	}
	if s.Tokens == nil {
		fail(http.StatusServiceUnavailable, "server_error", "this build was started without a token store")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(http.StatusBadRequest, "invalid_request", "the body is a form")
		return
	}
	f := r.PostForm
	switch {
	case f.Get("grant_type") != grantTokenExchange:
		fail(http.StatusBadRequest, "unsupported_grant_type", "the grant type is "+grantTokenExchange)
		return
	case f.Get("subject_token") == "":
		fail(http.StatusBadRequest, "invalid_request", "subject_token is the token being exchanged")
		return
	case f.Get("requested_token_type") != "" && f.Get("requested_token_type") != typeAccessToken:
		fail(http.StatusBadRequest, "invalid_request", "an access token is what this issues")
		return
	}
	sub := throttle.Subject{Source: sourceOf(r)}
	if s.Throttle != nil {
		if d := s.Throttle.Check(sub); !d.Allowed {
			fail(http.StatusTooManyRequests, "invalid_request", "too many failed attempts from this address. "+d.Why)
			return
		}
	}
	failed := func(kind string, err error) {
		if s.Throttle != nil {
			if d, alert := s.Throttle.Fail(sub); alert && s.OnAuthFailure != nil {
				s.OnAuthFailure(sub.Source, d.Failures)
			}
		}
		code := http.StatusBadRequest
		if errors.Is(err, dpop.ErrProof) {
			kind = "invalid_dpop_proof"
		}
		fail(code, kind, err.Error())
	}

	thumb := ""
	if len(r.Header.Values("DPoP")) > 0 {
		var err error
		if thumb, err = s.proofOf(r, ""); err != nil {
			failed("invalid_dpop_proof", err)
			return
		}
	}

	// The on-behalf-of half of RFC 8693: an agent presents its own
	// credential and a person's consented token together, and leaves with a
	// credential that is all three of the things it came from and nothing
	// more (exchangeOnBehalf, below).
	if f.Get("actor_token") != "" {
		s.exchangeOnBehalf(w, r, f, thumb, failed)
		return
	}
	role := auth.Role(strings.TrimSpace(f.Get("scope")))
	if role != "" && !role.Valid() {
		failed("invalid_scope", fmt.Errorf("the scope is a role: viewer, analyst, responder or admin"))
		return
	}
	resource := strings.TrimSpace(f.Get("resource"))
	now := time.Now()

	var secret string
	var tok auth.Token
	detail := map[string]string{"bound": fmt.Sprint(thumb != "")}
	switch f.Get("subject_token_type") {
	case typeAccessToken:
		var err error
		secret, tok, err = s.Tokens.ExchangeProved(f.Get("subject_token"), role, resource, 0, thumb, now)
		if err != nil {
			failed("invalid_grant", err)
			return
		}
		detail["how"] = "narrowed"
	case typeIDToken, typeJWT:
		// A token another system issued is not taken here: aertun trusts no
		// other issuer.
		failed("invalid_grant", errors.New("this console trusts no other issuer"))
		return
	default:
		failed("invalid_request", errors.New("subject_token_type is an Aertun access token, or an identity token (id_token or jwt) from an issuer a trust names"))
		return
	}
	if s.Throttle != nil {
		s.Throttle.Succeed(throttle.Subject{Principal: tok.Principal})
	}
	if err := s.save(); err != nil {
		fail(http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	detail["for"], detail["role"], detail["credential"] = tok.Principal, string(tok.Role), tok.ID
	s.audit("credential.exchanged", tok.Resource, detail)
	kind := "Bearer"
	if tok.Key != "" {
		kind = "DPoP"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exchangeAnswer{AccessToken: secret, IssuedTokenType: typeAccessToken,
		TokenType: kind, ExpiresIn: tok.ExpiresAt - now.Unix()})
}

// -- on-behalf-of -------------------------------------------------------------

// The second half of RFC 8693 at this endpoint. The first half narrows a
// credential the caller already holds; this one composes two into a chain:
// an agent (the client, authenticated by its own credential) exchanges the
// token a person consented to, and receives a token that acts for the person
// through the agent — never wider than either, and depth-capped at that one
// hop, because a chain of agents is a chain of revocation questions this
// store has one answer for (auth.MaxActChain).
//
// # The intersection, in one place
//
// The issued token's tools are the intersection of three allowlists, each
// owned by somebody different, each refusing independently:
//
//   - the registry's allowlist for the agent — what this organisation
//     decided the agent may call (internal/agentreg);
//   - the consent's bundle — what the person agreed to delegate to this
//     agent (internal/oauthas);
//   - the credential the agent presented — the caveat tool set of the run
//     token it holds, or nothing narrower than the registry when it holds
//     its plain bearer.
//
// Wider consent than registry: the registry wins. Wider registry than
// consent: the consent wins. A run token narrower than both: the run wins.
// An empty intersection is a refusal, not a best effort — "the agent and the
// person agree on nothing" is a decision, and issuing a token whose scope
// was nobody's would be issuing one with a lie where its scope goes.
//
// # What the issued token is
//
// A run-shaped credential: a secret minted by the token store (revocable,
// expiring, audience-bound to /mcp, grant-bound to the consent, parented to
// the consented token, carrying the act chain) with caveats signed by the
// store's run key, with the intersection as its tool caveat.
// That shape is the point: every gate that already exists — the registry
// gate, the tool allowlist gate, the caveat gate — checks it without knowing
// it was born here, and revoking the consent, the person's token or the
// agent reaches it through the machinery that already reaches everything
// else.
func (s *Server) exchangeOnBehalf(w http.ResponseWriter, r *http.Request,
	f url.Values, thumb string, failed func(string, error)) {

	if s.Tokens == nil {
		failed("invalid_request", errors.New("this build was started without a token store"))
		return
	}
	now := time.Now()
	refuse := func(kind string, err error) {
		if errors.Is(err, dpop.ErrProof) {
			kind = "invalid_dpop_proof"
		}
		failed(kind, err)
	}

	// The run key, wanted twice: to verify the credential the agent
	// presents, and to sign the caveats of the token this issues. Resolved
	// once, refused once — a store that cannot check chains cannot mint
	// them either.
	runKey := func() ([]byte, error) {
		return nil, errors.New("this server was started without the store's run key, so no run credential can be verified and no on-behalf-of token can be minted")
	}
	if s.RunKey != nil {
		runKey = s.RunKey
	}

	// The agent presents its own credential twice: in the Authorization
	// header, authenticating the request, and as actor_token, naming who is
	// acting. Both must resolve to the same stored token — the parameter is
	// the claim, the header is the proof of it, and an actor the request
	// cannot authenticate is a chain link nobody vouched for.
	headToken, _ := authzToken(r)
	if headToken == "" {
		refuse("invalid_client", errors.New("an on-behalf-of exchange presents the agent's credential in the Authorization header"))
		return
	}
	actorPresented := f.Get("actor_token")
	resolve := func(presented string) (*auth.Token, error) {
		secret := presented
		if half, ok := macaroon.Split(presented); ok {
			secret = half
		}
		t, err := s.Tokens.Authenticate(secret, now)
		if errors.Is(err, auth.ErrKeyBound) {
			if thumb == "" {
				return nil, errors.New("this credential is bound to a key, so the request carries its proof")
			}
			t, err = s.Tokens.AuthenticateProved(secret, "", thumb, now)
		}
		return t, err
	}
	actor, err := resolve(actorPresented)
	if err != nil {
		refuse("invalid_client", err)
		return
	}
	head, err := resolve(headToken)
	if err != nil {
		refuse("invalid_client", err)
		return
	}
	if head.ID != actor.ID {
		refuse("invalid_client", errors.New("actor_token and the Authorization header name different credentials; the actor is the agent making this request"))
		return
	}
	isRun := false
	if _, ok := macaroon.Split(actorPresented); ok {
		isRun = true
	}

	// The actor is the agent's own credential: not a resource token (an
	// access token from the consent flow is the person's, and a person
	// cannot be the acting half of the chain), and not itself a delegation
	// — that is the depth cap, refused here rather than truncated.
	if actor.Audience != "" {
		refuse("invalid_grant", errors.New("the actor is the agent's own credential, not an access token issued for a resource"))
		return
	}
	if len(actor.Act) > 0 {
		refuse("invalid_grant", fmt.Errorf("a delegation chain is at most %d long — the person and one agent — and this credential already acts for %s",
			auth.MaxActChain, strings.Join(actor.Act, " via ")))
		return
	}
	agent, ok := actorAgent(actor.Name)
	if !ok {
		refuse("invalid_grant", errors.New("the actor's credential names no registered agent; an agent:NAME token is what acts for somebody here"))
		return
	}
	entry, found, gerr := AgentRegistry.Get(agent)
	if gerr != nil || !found || entry.Status != agentreg.Active {
		refuse("invalid_grant", fmt.Errorf("agent %q is not active in the registry, so it may not act for anybody", agent))
		return
	}

	// The subject is the consented token: audience-bound to this
	// deployment's /mcp, grant-bound to a live consent, and carrying no
	// chain of its own (a token that already acts for somebody cannot be
	// the person end of another chain — the same cap, from the other side).
	aud := s.ownOrigin(r) + "/mcp"
	subSecret := f.Get("subject_token")
	subject, err := s.Tokens.AuthenticateFor(subSecret, aud, now)
	if errors.Is(err, auth.ErrKeyBound) {
		if thumb == "" {
			refuse("invalid_grant", errors.New("the consented token is bound to a key, so the request carries that key's proof"))
			return
		}
		subject, err = s.Tokens.AuthenticateProved(subSecret, aud, thumb, now)
	}
	if err != nil {
		refuse("invalid_grant", err)
		return
	}
	if subject.Grant == "" || subject.IsSession() {
		refuse("invalid_grant", errors.New("the subject of an on-behalf-of exchange is a token the consent flow issued, not a session or a plain credential"))
		return
	}
	if len(subject.Act) > 0 {
		refuse("invalid_grant", fmt.Errorf("the subject already acts for %s; a chain is at most %d long and cannot be extended",
			strings.Join(subject.Act, " via "), auth.MaxActChain))
		return
	}
	consent, cerr := s.Consents.Live(subject.Grant, now)
	if cerr != nil {
		refuse("invalid_grant", cerr)
		return
	}
	if consent.Agent != agent || consent.Principal != subject.Principal {
		refuse("invalid_grant", fmt.Errorf("the consent names agent %q acting for %q, and this exchange is agent %q acting for %q",
			consent.Agent, consent.Principal, agent, subject.Principal))
		return
	}
	bundle, ok := oauthas.BundleFor(consent.Scope)
	if !ok {
		refuse("invalid_grant", fmt.Errorf("the consent's scope %q is not a bundle this store has", consent.Scope))
		return
	}
	if !subject.Role.AtLeast(bundle.Role) {
		refuse("invalid_grant", fmt.Errorf("the consented token carries %s, less than the %s bundle needs", subject.Role, bundle.Name))
		return
	}

	// The third allowlist: the credential the agent presented. A run token
	// contributes its tool caveat — verified against the store's run key
	// first, because an unverified payload is a claim, and a claim that
	// widens is the one this check exists to refuse. A plain bearer
	// contributes nothing beyond the registry, which is already in the
	// intersection.
	actorTools := map[string]bool{}
	if isRun {
		privKey, kerr := runKey()
		if kerr == nil && len(privKey) != ed25519.PrivateKeySize {
			kerr = errors.New("the store's run key is not an Ed25519 private key, so no run credential can be verified")
		}
		if kerr != nil {
			refuse("invalid_grant", kerr)
			return
		}
		pubKey := ed25519.PrivateKey(privKey).Public().(ed25519.PublicKey)
		var expired error
		perr := macaroon.Verify(actorPresented, pubKey, func(cv macaroon.Caveat) error {
			switch cv.Kind {
			case macaroon.KindTool:
				for _, t := range cv.Tools() {
					actorTools[t] = true
				}
			case macaroon.KindExp:
				if at, e := cv.Int(); e == nil && now.Unix() >= at {
					expired = fmt.Errorf("the agent's run credential ended at %s",
						time.Unix(at, 0).UTC().Format(time.RFC3339))
				}
			}
			return nil
		})
		switch {
		case perr != nil:
			refuse("invalid_grant", perr)
			return
		case expired != nil:
			refuse("invalid_grant", expired)
			return
		case len(actorTools) == 0:
			refuse("invalid_grant", errors.New("the run credential carries no tool caveat, so it was not minted by this store"))
			return
		}
	}

	// The intersection itself. The refusal names the three bounds in the
	// order the design reads the decision: registry, consent, credential.
	var granted []string
	for _, t := range bundle.Tools {
		if !entry.MayUse(t) || (isRun && !actorTools[t]) {
			continue
		}
		granted = append(granted, t)
	}
	if len(granted) == 0 {
		refuse("invalid_scope", fmt.Errorf(
			"nothing is common to all three bounds: the registry allows %s, the consent carries %s, the credential carries %s",
			strings.Join(entry.Allow, ","), strings.Join(bundle.Tools, ","),
			runToolsWord(actorPresented, isRun)))
		return
	}

	// Minutes, not hours: this is a working token for one stretch of one
	// run, capped by everything that legitimises it. No refresh — the agent
	// exchanges again while the consent and its credential live, and both
	// of those are the durable story.
	ttl := auth.DefaultSessionTTL
	for _, ends := range []int64{subject.ExpiresAt, consent.ExpiresAt, actor.ExpiresAt} {
		if left := time.Unix(ends, 0).Sub(now); left < ttl {
			ttl = left
		}
	}
	if ttl <= 0 {
		refuse("invalid_grant", errors.New("the consent or a credential ends too soon to mint anything"))
		return
	}

	// The mint. Everything the gates will check is set here: the run-shaped
	// name (registry gate, allowlist gate), the parent and the grant
	// (revocation cascade), the audience (/mcp only), the act chain (the
	// depth cap's record), and the caveats signed under the run key.
	name := agentreg.TokenPrefix + agent + "/obo-" + consent.ID
	act := []string{subject.Principal, agent}
	// Everything that can refuse is settled before the credential exists,
	// so a refusal never leaves an issued token behind in the store.
	key, kerr := runKey()
	if kerr != nil {
		refuse("invalid_request", kerr)
		return
	}
	toolCaveat, terr := macaroon.ToolCaveat(granted...)
	if terr != nil {
		refuse("invalid_request", terr)
		return
	}
	purposeCaveat, perr := macaroon.PurposeCaveat(bundle.Name)
	if perr != nil {
		refuse("invalid_request", perr)
		return
	}
	secret, tok, ierr := s.Tokens.IssueForAgent(name, subject.Principal,
		bundle.Role, auth.Scope{ReadOnly: bundle.ReadOnly}, agent,
		consent.ID, aud, subject.ID, act, thumb, ttl, now)
	if ierr != nil {
		refuse("invalid_request", ierr)
		return
	}
	token, merr := macaroon.Mint(secret, key, name, toolCaveat, purposeCaveat,
		macaroon.ExpCaveat(time.Unix(tok.ExpiresAt, 0)))
	if merr != nil {
		refuse("invalid_request", merr)
		return
	}
	if err := s.save(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "server_error", "error_description": err.Error()})
		return
	}
	if s.Throttle != nil {
		s.Throttle.Succeed(throttle.Subject{Principal: agent})
	}
	if s.AuditAgent != nil {
		// Closed detail: the bundle word, the depth, the tool set — words
		// from closed vocabularies, so the aertun/agent telemetry a rule
		// reads carries facts rather than prose. Who the agent acts for is
		// in the audit log's own record of this exchange and nowhere
		// wider: a person's name is personal data, and the event store is
		// read wider than the log.
		s.AuditAgent("agent.exchanged", "/mcp", agent, map[string]string{
			"scope": bundle.Name, "depth": fmt.Sprint(len(act)),
			"tools": strings.Join(granted, ","), "run": "obo-" + consent.ID,
			"bound": fmt.Sprint(thumb != ""),
		})
	}
	kind := "Bearer"
	if thumb != "" {
		kind = "DPoP"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exchangeAnswer{AccessToken: token,
		IssuedTokenType: typeAccessToken, TokenType: kind,
		ExpiresIn: tok.ExpiresAt - now.Unix(), Scope: bundle.Name})
}

// actorAgent is the registered agent a credential's name claims, and whether
// it claims one at all: the agent: prefix the registry owns, optionally with
// a run after the slash. The claim is the name's; the registry decides
// whether it names anybody, which is the caller's next question.
func actorAgent(name string) (string, bool) {
	bound, ok := agentreg.Bind(name)
	if !ok {
		return "", false
	}
	agent, _, found := strings.Cut(bound, "/")
	if !found {
		return agent, true
	}
	if !agentreg.ValidName(agent) {
		return "", false
	}
	return agent, true
}

// runToolsWord is the credential's tool set as a refusal names it: the
// caveat's own words when there were any, the registry's when the credential
// narrowed nothing.
func runToolsWord(presented string, isRun bool) string {
	if !isRun {
		return "whatever the registry allows"
	}
	if t, ok := macaroon.Parse(presented); ok {
		for _, cv := range t.Caveats() {
			if cv.Kind == macaroon.KindTool {
				return cv.Value
			}
		}
	}
	return "no tools"
}
