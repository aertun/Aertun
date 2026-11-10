// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/admin"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/config"
	"github.com/aertun/aertun/internal/dpop"
	"github.com/aertun/aertun/internal/find"
	"github.com/aertun/aertun/internal/macaroon"
	"github.com/aertun/aertun/internal/mcp"
	"github.com/aertun/aertun/internal/proving"
)

// The MCP surface is the third interface onto the same store, and every
// operation here goes through the same gates as the command line and the
// console. It reads, and proposes; it does not act. An agent reading events
// is reading text an attacker chose, so nothing on this surface changes who
// may do what, approves an act, or reaches another platform.

func cmdMCP(root string, args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	list := fs.Bool("list", false, "print the operations and exit")
	twinAt := fs.String("twin", "", "answer from the snapshot FILE that "+
		"aertun twin record wrote instead of from the store: the same answer "+
		"each time, every value labelled with whether an attacker could have "+
		"written it, and nothing can be changed")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var srv *mcp.Server
	// called audits each tools/call against the store. The twin has no
	// store: it reads one file and writes nothing, and what it replays was
	// put in the audit log when the snapshot was recorded.
	var called func(json.RawMessage, *mcp.Response)
	if *twinAt != "" {
		s, err := openTwin(*twinAt)
		if err != nil {
			return err
		}
		srv = s
	} else {
		caller := resolveCaller(root, flagToken)
		srv = buildMCP(root, caller)
		called = func(params json.RawMessage, resp *mcp.Response) {
			auditStdioCall(root, caller, params, resp)
		}
	}

	if *list {
		for _, op := range srv.Operations() {
			kind := "read"
			if op.Writes {
				kind = "write"
			}
			fmt.Printf("  %-22s %-6s %s\n", op.Name, kind, op.Summary)
		}
		fmt.Printf("\n  %s%d operations behind 3 tools; an agent loads only what it "+
			"searches for%s\n", dim, len(srv.Operations()), reset)
		return nil
	}

	// stdio. A hosted deployment fronts this with streamable HTTP, and the
	// framing is the only difference — the routing and the gates are identical,
	// which is why they live in buildMCP rather than in a transport.
	return serveLines(srv, os.Stdin, os.Stdout, called)
}

// serveStdio answers the line-framed JSON-RPC protocol on a pair of streams.
//
// Every tools/call is audited (auditMCPCall), as the HTTP transport's Called
// hook audits its own. An agent that scrapes the findings queue over stdio
// leaves the same record as one that scrapes it over HTTP: without this, the
// transport a caller happened to choose would decide whether anything could
// tell it had been — and the detection rules that read these records as
// events under the agent source watch stdio agents too.
func serveStdio(root string, srv *mcp.Server, caller *Caller, r io.Reader, w io.Writer) error {
	return serveLines(srv, r, w, func(params json.RawMessage, resp *mcp.Response) {
		auditStdioCall(root, caller, params, resp)
	})
}

// serveLines is the line framing alone: one JSON-RPC request per line in,
// one reply per line out, and called told of every tools/call when it is
// not nil. serveStdio hands it the audit; the context twin hands it
// nothing, because the twin answers from a file and has no store to record
// into.
func serveLines(srv *mcp.Server, r io.Reader, w io.Writer,
	called func(json.RawMessage, *mcp.Response)) error {
	in := bufio.NewScanner(r)
	in.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	out := json.NewEncoder(w)

	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var req mcp.Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = out.Encode(mcp.Response{JSONRPC: "2.0",
				Error: &mcp.Error{Code: mcp.CodeParse, Message: err.Error()}})
			continue
		}
		resp := srv.Handle(req)
		if req.Method == "tools/call" && called != nil {
			called(req.Params, resp)
		}
		// A notification has no id and expects no reply.
		if len(req.ID) == 0 {
			continue
		}
		if err := out.Encode(resp); err != nil {
			return err
		}
	}
	return in.Err()
}

// auditStdioCall writes the audit record for one tools/call on stdio: the
// tool and operation the request named, and the answer the caller was given.
// The record itself is written by auditMCPCall, which the HTTP transport's
// hook writes too, so nothing downstream can tell — or needs to tell — which
// transport carried the call.
func auditStdioCall(root string, caller *Caller, params json.RawMessage, resp *mcp.Response) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	_ = json.Unmarshal(params, &p)
	operation := ""
	if len(p.Arguments) > 0 {
		var a struct {
			Operation string `json:"operation"`
		}
		_ = json.Unmarshal(p.Arguments, &a)
		operation = a.Operation
	}
	auditMCPCall(root, caller.Name, p.Name, operation, resp.Error)
}

// auditMCPCall writes the audit record for one tools/call, whichever
// transport carried it: action mcp.call under the fixed mcp-client
// principal, with the calling client in the detail. A refusal is a denied
// outcome, not a failure, so a rule reading these events tells an agent
// that was told no from one that broke.
//
// Reported rather than returned: the call has happened and the caller has
// its answer, and a record that could not be written is a thing to say
// loudly, not a reply to take back. The writes an agent makes are refused
// outright unless the log can take their record (auditReady, in buildMCP's
// gate); reads go on and are recorded here, which is what tells this
// process the log is back.
func auditMCPCall(root, client, tool, operation string, rerr *mcp.Error) {
	outcome := audit.Success
	if rerr != nil {
		outcome = audit.Failure
		if rerr.Code == mcp.CodeRefused {
			outcome = audit.Denied
		}
	}
	record(root, audit.Record{
		Action: "mcp.call", Resource: "/mcp", Outcome: outcome,
		Principal: "mcp-client", Kind: audit.KindAI, Model: "mcp-client",
		Verified: false,
		Detail: map[string]string{
			"tool": tool, "operation": operation, "client": client},
	})
}

// The agent interface over HTTP, mounted by serve beside the console. The
// framing is the only difference from stdio: buildMCP is the whole surface,
// and this transport only carries it, so the role gate, the
// read-tool-cannot-write split and the audit-first rule for an agent's
// writes are the same lines of code on both.
//
// wellKnownMCP is where RFC 9728 puts a resource's own metadata. The path
// carries the resource's suffix because one origin may host several
// protected resources, and the unsuffixed path would make a second one
// impossible without moving the first.
const wellKnownMCP = "/.well-known/oauth-protected-resource/mcp"

// mountMCP puts the agent interface and its discovery document on the
// console's server.
//
// It is mounted beside the console's handler rather than inside it on
// purpose. The console answers a person holding a session cookie; this
// answers a program holding a bearer token, resolved by the transport's
// Authenticate hook on every request. Standing the endpoint outside the
// console's middleware is what keeps the two credentials from mixing: a
// console cookie must neither open the agent interface, nor — the sharper
// edge — must the absence of one close it, and a page that tries to drive a
// signed-in person's browser at this endpoint is stopped by the origin
// check before any of that matters.
func mountMCP(mux *http.ServeMux, root string, cfg *config.Config, addr string) {
	// The resource is named for the origin the operator chose — the
	// configured one, or the address they listen on — not for whatever
	// host a request arrives claiming: a Host header is an input, not an
	// identity. With admin.base_url set, every request is checked against
	// it too, so a token's audience and a proof's address are what the
	// metadata says, behind a proxy as in front of one.
	origin := publicOrigin(cfg, addr)
	base := cfg.Raw("admin.base_url")

	// One replay window for the endpoint's life: a DPoP proof is good for
	// one request, and the remembering has to outlive each of them.
	var proofs dpop.Replays
	origins := mcpOrigins(cfg, addr)

	mux.Handle("/mcp", &mcp.Endpoint{
		Metadata: origin + wellKnownMCP,
		// Key-bound tokens are accepted here with the proof their key made
		// for the request, which this surface becomes alongside
		// /token/exchange (ErrKeyBound names it).
		DPoP: dpop.AlgorithmNames(),
		Authenticate: func(r *http.Request, token string) (*mcp.Caller, error) {
			c, err := agentCaller(root, r, token, &proofs, base)
			if err != nil {
				return nil, err
			}
			return &mcp.Caller{Principal: c.Name, Data: c}, nil
		},
		Build: func(r *http.Request, c *mcp.Caller) (*mcp.Server, error) {
			// The caller Authenticate resolved, carried to the same gates
			// the stdio path applies to the token the CLI read.
			return buildMCP(root, c.Data.(*Caller)), nil
		},
		SameOrigin: func(o string) bool { return origins[o] },
		Called: func(r *http.Request, c *mcp.Caller, tool, operation string, rerr *mcp.Error) {
			auditMCPCall(root, c.Principal, tool, operation, rerr)
		},
	})
	// The document a 401 points at: what this resource is, and the one
	// authorization server that issues for it. The AS is this same
	// deployment (mounted beside the console, oauthserve.go): its
	// authorization endpoint asks the person signed in to the console, and
	// its tokens arrive resource-bound to exactly this address. Named
	// here and nowhere else — the issuer a client discovers is the issuer
	// this resource answers for.
	mux.Handle(wellKnownMCP, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              origin + "/mcp",
			"authorization_servers": []string{origin},
		})
	}))
}

// agentCaller resolves the bearer token an HTTP request presented against
// the same token store the command line and the console read. There is no
// second store and no other issuer, so a token from `aertun token issue` is
// the credential here, and the caller it becomes carries the token's own
// limits — role, path, scope — which is what caps an agent exactly as it
// caps a person.
//
// The resource asked about is /mcp, so a token bound to one audience — the
// OAuth shape, the day one is issued — is accepted only here, and only when
// /mcp is the audience it was issued for. That is the RFC 8707 seam
// internal/mcp's package comment names, closed at the one place it can be.
func agentCaller(root string, r *http.Request, token string, proofs *dpop.Replays, base string) (*Caller, error) {
	// A run credential arrives as one string in two halves — the secret the
	// store holds the hash of, then its caveat payload (internal/macaroon).
	// The halves are split here for the same reason resolveCaller splits
	// them on stdio: the store decides the bearer without knowing caveats
	// exist, and the caveat gate — not the store — refuses a payload that
	// does not verify. The whole string is carried to that gate, so what is
	// checked is what was presented. This surface once refused the dotted
	// form at the door because nothing behind the door checked the payload;
	// the exchange now mints run-shaped tokens (agent:NAME/obo-GRANT, bound
	// to this audience), so the door learned the split and the gate behind
	// it learned nothing new.
	presented := token
	if half, ok := macaroon.Split(token); ok {
		token = half
	}
	toks, err := loadTokens(root)
	if err != nil {
		return nil, fmt.Errorf("the token store could not be read: %v", err)
	}
	now := time.Now()
	// The resource this request is asking about is this request's own /mcp
	// address (RFC 8707): a token audience-bound to the agent interface is
	// accepted here, and a token bound to any other resource — the admin, a
	// future second interface, another deployment — is not, which is what
	// keeps an app's OAuth token from being a way into everything else.
	resource := mcpRequestURL(root, r, base)
	tok, err := toks.AuthenticateFor(token, resource, now)
	if errors.Is(err, auth.ErrKeyBound) {
		// The token is bound to a key, so the request must carry the proof
		// that key made for it, checked here against this request's method
		// and address rather than merely presented.
		heads := r.Header.Values("DPoP")
		if len(heads) != 1 {
			return nil, fmt.Errorf("%w: a key-bound token comes with exactly one DPoP proof",
				dpop.ErrProof)
		}
		thumb, perr := dpop.Check(heads[0], r.Method, mcpRequestURL(root, r, base), token, now, proofs)
		if perr != nil {
			return nil, perr
		}
		tok, err = toks.AuthenticateProved(token, resource, thumb, now)
	}
	if err != nil {
		return nil, err
	}
	// Using a token records that it was used, over HTTP as over the command
	// line, so `token stale` can find credentials nobody needs any more.
	_ = saveTokens(root, toks)
	c := callerFromToken(tok)
	if presented != token {
		c.RunToken = presented
	}
	return c, nil
}

// mcpOrigins is the page origins the agent interface answers: this server's
// own addresses, and nothing else. A request with no Origin header is not
// from a page and never reaches this check (http.go); this decides only
// which pages may drive a person's browser at the endpoint.
func mcpOrigins(cfg *config.Config, addr string) map[string]bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	names := []string{host}
	// The console is opened as localhost when it listens on a bare address
	// (serve says so on startup), so the loopback names all name this
	// server, and a page served from any of them is one of ours.
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		names = append(names, "127.0.0.1", "localhost", "::1")
	}
	scheme := "http"
	if cfg.Bool("admin.behind_tls_proxy") {
		scheme = "https"
	}
	out := map[string]bool{}
	for _, h := range names {
		out[scheme+"://"+net.JoinHostPort(h, port)] = true
	}
	if base := cfg.Raw("admin.base_url"); base != "" {
		out[base] = true
	}
	return out
}

// mcpRequestURL is the address a request was made to, as a DPoP proof and
// a token's audience name it: the configured origin when there is one
// (base, admin.base_url as serve started with it), otherwise the scheme
// from the socket or the trusted-proxy setting and the host as the request
// came in; the path as it came in either way.
func mcpRequestURL(root string, r *http.Request, base string) string {
	if base != "" {
		return base + r.URL.Path
	}
	scheme := "http"
	if r.TLS != nil || mustConfig(root).Bool("admin.behind_tls_proxy") {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

// opFind is written once, for the agent interface and the context twin
// (mcptwin.go) alike.
var opFind = mcp.Operation{
	Name: "find", NeedsRole: "viewer",
	Summary: "find a screen by words",
	Detail: "Words, not a query: there is no syntax, and a colon or a " +
		"quote is a character in a word.",
	Args: map[string]string{
		"query": "the words to look for",
		"limit": "optional, default 20",
	},
	Area:     "/",
	Keywords: []string{"find", "search", "where", "lookup", "locate", "screen"},
}

func buildMCP(root string, caller *Caller) *mcp.Server {
	srv := mcp.NewServer("aertun", version)

	// Every operation is authorised here, from the role it declares, and
	// each handler checks again: a second look costs nothing, and a new
	// operation does not need anybody to remember.
	srv.Authorise = func(op mcp.Operation) error {
		action, err := actionForRole(op.NeedsRole)
		if err != nil {
			// An operation with no role declared is refused rather than
			// allowed. The alternative is the behaviour being fixed: a new
			// operation is open until somebody notices.
			return fmt.Errorf("%q declares no role, so it cannot be "+
				"authorised: %v", op.Name, err)
		}
		// A change made through this interface is an agent's, and is
		// refused while its record could not be written (auditReady).
		// Reads go on, and their records are what tell this process the
		// log is back.
		if op.Writes {
			if err := auditReady(root); err != nil {
				return err
			}
		}
		if op.Area != "" {
			return authoriseUnder(root, caller, action, op.Area)
		}
		return authorise(root, caller, action, "/")
	}

	// Screens, by words. The settings are left out on this surface rather
	// than gated: a key's summary describes a control, and reconnaissance
	// over the controls is what an injected instruction would ask for first.
	srv.Register(opFind, func(a map[string]any) (any, error) {
		query, _ := a["query"].(string)
		if strings.TrimSpace(query) == "" {
			return nil, fmt.Errorf("find needs a query")
		}
		limit := 20
		if n, ok := a["limit"].(float64); ok && n > 0 {
			limit = int(n)
		}
		hits := find.Search(query, find.Sources{Screens: admin.Screens()}, limit)
		if len(hits) == 0 {
			return "nothing matched", nil
		}
		var b strings.Builder
		for _, h := range hits {
			fmt.Fprintf(&b, "%s\t%s\t%s\t%s\n", h.Kind, h.Title, h.Path, h.Why)
		}
		return strings.TrimSpace(b.String()), nil
	})

	registerSecurityOps(srv, root, caller)
	registerEstateOps(srv, root, caller)
	registerOps(srv, proving.Ops(root), root, caller)

	return srv
}

// actionForRole maps the role an operation declares to the action checked.
//
// Roles rather than actions on the Operation because that is what an agent is
// shown, and a surface that tells a caller "needs analyst" and then checks
// something else would be lying to it.
func actionForRole(role string) (auth.Action, error) {
	switch role {
	case "viewer":
		return auth.ActView, nil
	case "analyst":
		return auth.ActTriage, nil
	case "responder":
		return auth.ActRespond, nil
	case "admin":
		// The workforce summary is an administrator's: a person's score is
		// a file on an employee.
		return auth.ActGrant, nil
	}
	return "", fmt.Errorf("%q is not a role this program has", role)
}
