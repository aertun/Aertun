// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/agentreg"
	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/fetch"
	"github.com/aertun/aertun/internal/macaroon"
	"github.com/aertun/aertun/internal/oauthas"
)

// The register of agents this organisation runs — the IA-9 object, and the
// thing AC-2 asks to be able to review and to switch off.
//
// Two halves hold it up, and both live in this file's colleagues rather
// than here: the binding (a token named agent:NAME identifies as that
// agent, caller.go) and the enforcement (every gate consults the registry
// before the policy, and the agent interface allows an agent only the tools
// its entry lists, mcpsecurity.go). This file is the read-and-change
// surface over the same register, so `agent list` and the gate can never
// disagree about who exists.

// agentsPath is the registry, beside the policy and the token store, with
// their permissions: it names who may act, which is not world-readable
// material.
func agentsPath(root string) string { return filepath.Join(root, "agents.json") }

func agentStore(root string) agentreg.Store {
	return agentreg.Store{Path: agentsPath(root)}
}

// agentMapsPath is the recorder-host to agent mapping, beside the registry
// it names. A sibling file rather than rows inside agents.json (see
// internal/agentreg for the whole argument): the registry is the review of
// who may act, and where evidence comes from is a declaration that changes
// on the recorders' cadence, not the register's. Same discipline either
// way — one document, changed whole under its lock.
func agentMapsPath(root string) string { return filepath.Join(root, "agentmaps.json") }

func agentMapStore(root string) agentreg.MapStore {
	return agentreg.MapStore{Path: agentMapsPath(root), Registry: agentsPath(root)}
}

func agentUsage() error {
	return fmt.Errorf("usage: aertun agent list | add NAME --owner WHO --allow TOOL[,TOOL] [--note \"…\"] | " +
		"allow NAME (--add | --remove) TOOL[,TOOL] | maps NAME --host HOST [--remove] | " +
		"token NAME --tools TOOL[,TOOL] --for-run ID " +
		"[--hours N] [--purpose observe|triage] [--calls N] [--level N] | disable NAME --why \"…\" | " +
		"enable NAME --why \"…\" | consents [revoke ID] | " +
		"reconcile NAME --since DATE --key F [--telemetry ID] [--window 2m] | help")
}

// cmdAgent manages the agent register.
func cmdAgent(root string, args []string) error {
	if len(args) == 0 {
		return agentHelp()
	}
	caller := resolveCaller(root, "")
	// note records a change to the register under the caller's own name:
	// who added what, who pulled which switch. The action is what the
	// detections and the access reviews read, so it names the verb and the
	// register in the log's dotted style (agent.add, agent.disable).
	note := func(action, name string, extra map[string]string) error {
		d := map[string]string{"agent": name}
		for k, v := range extra {
			d[k] = v
		}
		return recordE(root, caller.auditRecord(action, "/agents/"+name,
			audit.Success, d))
	}
	switch args[0] {
	case "help":
		return agentHelp()
	case "list":
		return agentList(root)
	case "add":
		return agentAdd(root, caller, args[1:], note)
	case "allow":
		return agentAllow(root, caller, args[1:], note)
	case "maps":
		return agentMaps(root, caller, args[1:], note)
	case "token":
		return agentMint(root, caller, args[1:], note)
	case "disable":
		return agentDisable(root, caller, args[1:], note)
	case "enable":
		return agentEnable(root, caller, args[1:], note)
	case "consents":
		return agentConsents(root, caller, args[1:], note)
	case "reconcile":
		return agentReconcile(root, caller, args[1:])
	}
	return agentUsage()
}

func agentList(root string) error {
	agents, err := agentStore(root).Load()
	if err != nil {
		return err
	}
	// The mapping is read beside the register so the review sees both
	// halves of "what may act, and where its evidence comes from". A
	// mapping that cannot be read is not an empty one — the same line the
	// registry itself draws — because a listing that quietly forgot the
	// declarations would show every host as unmapped and nobody would know.
	maps, err := agentMapStore(root).Load()
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"agents": agents}) {
		return nil
	}
	if len(agents) == 0 {
		w.Human("  no agents are registered; aertun agent help says what that buys\n")
		return nil
	}
	for _, a := range agents {
		state := green + "active" + reset
		if a.Status == agentreg.Disabled {
			state = red + "disabled" + reset
		}
		allow := strings.Join(a.Allow, ", ")
		if allow == "" {
			allow = dim + "no tools" + reset
		}
		w.Human("  %s%s%s  %s  owner %s  %s\n", bold, a.Name, reset, state, a.Owner, allow)
		if a.Note != "" {
			w.Human("    %s\n", a.Note)
		}
		if hosts := agentreg.Hosts(maps, a.Name); len(hosts) > 0 {
			w.Human("    %sruns on %s%s\n", dim, strings.Join(hosts, ", "), reset)
		}
		if a.Status == agentreg.Disabled && a.DisabledWhy != "" {
			w.Human("    %sdisabled: %s%s\n", yellow, a.DisabledWhy, reset)
		}
		w.Human("    %sregistered %s by %s; changed %s by %s%s\n", dim,
			a.CreatedAt.Format("2 Jan 2006"), a.CreatedBy,
			a.ChangedAt.Format("2 Jan 2006"), a.ChangedBy, reset)
	}
	w.Human("\n  %sa token named agent:NAME identifies as that agent and is "+
		"refused by every gate unless it is registered here%s\n", dim, reset)
	return nil
}

// agentAdd registers an agent. The privilege is the dispatch table's: an
// administrator's, because adding one decides what may act in this store.
func agentAdd(root string, caller *Caller, args []string,
	note func(string, string, map[string]string) error) error {

	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	owner := fs.String("owner", "", "the person who answers for what this agent does")
	allow := fs.String("allow", "", "the tools it may call, comma-separated: "+
		strings.Join(agentreg.Tools(), ", "))
	noteText := fs.String("note", "", "why this agent exists, on the record")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return agentUsage()
	}
	a := agentreg.Agent{Name: pos[0], Owner: *owner, Allow: splitList(*allow),
		Note: strings.TrimSpace(*noteText), CreatedBy: caller.Name}
	if err := agentStore(root).Add(a, time.Now().UTC()); err != nil {
		return err
	}
	w.Human("registered %s%s%s (owner %s, allowed %s)\n", bold, pos[0], reset,
		*owner, strings.Join(splitList(*allow), ", "))
	// The register does not mint the credential: issuing a token named
	// agent:NAME is the owner's separate act with `token issue`, and the
	// two are separate on purpose — a register that issued credentials
	// could not be a list anybody dared to add to.
	w.Human("  %sno credential exists yet; a token issued as %s%s%s binds to "+
		"this entry:%s\n", dim, agentreg.TokenPrefix, pos[0], "", reset)
	w.Human("    aertun token issue %s%s --principal %s --role viewer\n",
		agentreg.TokenPrefix, pos[0], pos[0])
	return note("agent.add", pos[0], map[string]string{
		"owner": *owner, "allow": strings.Join(splitList(*allow), ",")})
}

// agentAllow widens or narrows an entry's tool allowlist.
func agentAllow(root string, caller *Caller, args []string,
	note func(string, string, map[string]string) error) error {

	fs := flag.NewFlagSet("allow", flag.ContinueOnError)
	add := fs.String("add", "", "tools to allow, comma-separated")
	remove := fs.String("remove", "", "tools to refuse, comma-separated")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || (*add == "" && *remove == "") {
		return agentUsage()
	}
	s := agentStore(root)
	if err := s.Allow(pos[0], splitList(*add), splitList(*remove), caller.Name,
		time.Now().UTC()); err != nil {
		return err
	}
	a, _, err := s.Get(pos[0])
	if err != nil {
		return err
	}
	w.Human("%s now allowed %s\n", pos[0], strings.Join(a.Allow, ", "))
	action := "agent.allow"
	extra := map[string]string{"allow": strings.Join(a.Allow, ",")}
	if *remove != "" {
		// A distinct action for the narrowing half, because "allow" reading
		// backwards in a log search is how a removed tool goes unnoticed.
		action = "agent.disallow"
		extra["removed"] = *remove
	}
	if *add != "" {
		extra["added"] = *add
	}
	return note(action, pos[0], extra)
}

// agentMaps declares — or takes back — which recorder host an agent runs
// on. The `allow` grammar on purpose: one verb, two directions, and the
// audit actions say which way (agent.mapped, agent.unmapped).
//
// This is the onboarding act the watch-then-call correlation was refused
// for lacking. The collector's evidence says a file changed on a host and
// never who changed it; an operator who knows the estate can say which
// agents run there, and the declaration — not a guess by the program — is
// what the collector's events then carry (raw.agents, cmd/aertun's ingest
// path). The privilege is the dispatch table's `agent` row, the
// register's own: deciding where an agent's name may be joined is deciding
// what the register's names mean in the evidence.
func agentMaps(root string, caller *Caller, args []string,
	note func(string, string, map[string]string) error) error {

	fs := flag.NewFlagSet("maps", flag.ContinueOnError)
	host := fs.String("host", "", "the recorder host this agent runs on, "+
		"spelled the way the recorder reports it")
	remove := fs.Bool("remove", false, "take the declaration back")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || strings.TrimSpace(*host) == "" {
		return agentUsage()
	}
	if *remove {
		if err := agentMapStore(root).Unmap(*host, pos[0], caller.Name,
			time.Now().UTC()); err != nil {
			return err
		}
		// Said out loud because the timing is the honest limit: what the
		// next push carries is decided at the next push, so an event that
		// arrives meanwhile still names the agent, and that event is the
		// audit trail's to explain, not this command's to rewrite.
		w.Human("%s no longer runs on %s%s\n", pos[0], strings.TrimSpace(*host),
			dim+"; the next push from it carries nothing"+reset)
		return note("agent.unmapped", pos[0], map[string]string{
			"host": strings.TrimSpace(*host)})
	}
	if err := agentMapStore(root).Map(*host, pos[0], caller.Name,
		time.Now().UTC()); err != nil {
		return err
	}
	w.Human("%s%s%s is declared to run on %s\n", bold, pos[0], reset,
		strings.TrimSpace(*host))
	w.Human("  %sevidence from that host carries its name, because the "+
		"operator said so and not because the program guessed%s\n", dim, reset)
	return note("agent.mapped", pos[0], map[string]string{
		"host": strings.TrimSpace(*host)})
}

// agentMint mints a run token: a caveat-bound credential for one run of a
// registered agent, where a run is bounded by caveats the store's run key
// signs and the tool gate checks.
//
// The register decides who the agent is; this decides what one run of it
// may do, and it can only narrow. Every tool named must be one the agent's
// own entry allows; the role minted is the least the tools need; a run
// that may not write is issued read-only. The privilege is the dispatch
// table's `agent` row — an administrator's — which is the conservative
// fallback for a subcommand the table does not name separately: minting a
// credential is at least the weight of changing the register, and a
// narrower row (the manage-tokens permission, like `token` itself) is a
// decision for the table's next edit rather than a guess made here.
func agentMint(root string, caller *Caller, args []string,
	note func(string, string, map[string]string) error) error {

	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	tools := fs.String("tools", "", "the tools this run may call, "+
		"comma-separated, within what the agent is allowed")
	run := fs.String("for-run", "", "the id of the run this is minted for")
	hours := fs.Int("hours", 8, "how long the run lives, 1 to 24")
	purpose := fs.String("purpose", "", "why the run exists: observe (reads) "+
		"or triage (reads and proposals)")
	calls := fs.Int("calls", 0, "at most this many calls under the token, "+
		"counted by the process that verifies it")
	level := fs.Int("level", -1, "the run's autonomy bound, 0 to 3")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return agentUsage()
	}
	tok, err := issueRunToken(root, caller, pos[0], *run, splitList(*tools),
		*hours, *purpose, *calls, *level)
	if err != nil {
		return err
	}
	// The token is printed the way every minted secret is: bare and bold,
	// on its own line, because the next thing that happens to it is a copy
	// into wherever the run's credential lives.
	fmt.Printf("%s%s%s\n", bold, tok, reset)
	// Said out loud because it is the honest reach of the thing: the
	// caveats are checked on the command line's agent interface, which
	// is where a run rides; the HTTP interface refuses the dotted form at
	// the door, because its credential half is the only half the store
	// holds a hash of — fail-closed, by shape.
	w.Human("  %sa run token for %s: present it with --token; its caveats "+
		"are checked where its tools are called, and its bare credential "+
		"half is refused by every gate%s\n", dim, pos[0], reset)
	detail := map[string]string{"run": *run,
		"tools": strings.Join(splitList(*tools), ",")}
	if *purpose != "" {
		detail["purpose"] = *purpose
	}
	return note("agent.token", pos[0], detail)
}

// issueRunToken is the mint's core: validate the bounds against the
// register, mint a credential with the token store's own machinery, and
// sign its caveats with the store's run key.
//
// Two authorities are involved and both are the store's existing ones: the
// credential half is issued by auth.TokenStore.IssueScoped — so the
// issuer's role caps it, its expiry is a real expiry, revocation reaches
// it and the kill switch's sweep kills it — and the caveat half is signed
// by the run key beside the register (ensureRunKey), which nothing else in
// the store can re-make. A run token is therefore verified against the
// same store twice over: as a credential, everywhere, and as a signed set
// of caveats, at the tool gate.
func issueRunToken(root string, caller *Caller, name, run string,
	tools []string, hours int, purpose string, calls, level int) (string, error) {

	if !caller.Verified {
		return "", fmt.Errorf("minting a run token needs a verified " +
			"identity: the credential carries whoever mints it")
	}
	a, found, err := agentStore(root).Get(name)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("there is no agent %q (aertun agent list)", name)
	}
	if a.Status != agentreg.Active {
		return "", fmt.Errorf("agent %q is disabled, and a run is not minted "+
			"for an agent that may not act", name)
	}
	if len(tools) == 0 {
		return "", fmt.Errorf("a run token names the tools it may call; one " +
			"that names none is the agent's whole bearer and no narrower")
	}
	writes := false
	for _, t := range tools {
		if !agentreg.ValidTool(t) {
			return "", fmt.Errorf("%q is not a tool the agent interface "+
				"serves; the tools are %s", t,
				strings.Join(agentreg.Tools(), ", "))
		}
		if !a.MayUse(t) {
			return "", fmt.Errorf("%q allows %s nothing it may pass on: the "+
				"register allows it %s, and a run token cannot start wider "+
				"than the agent it runs for", name, t,
				strings.Join(a.Allow, ", "))
		}
		if t == "aertun_write" {
			writes = true
		}
	}
	if !agentreg.ValidName(run) {
		return "", fmt.Errorf("%q is not a run id: 2 to 40 lowercase letters, "+
			"digits and hyphens, because it becomes part of a token name", run)
	}
	if hours < 1 || hours > 24 {
		return "", fmt.Errorf("a run lives 1 to 24 hours, not %d: a run token "+
			"is the short-lived half of the design, and one with no end is "+
			"the bearer it was meant not to be", hours)
	}
	if purpose != "" && !macaroon.ValidPurpose(purpose) {
		return "", fmt.Errorf("%q is not a purpose this program has; the "+
			"words are %s (reads) and %s (reads and proposals)", purpose,
			macaroon.PurposeObserve, macaroon.PurposeTriage)
	}
	if purpose == macaroon.PurposeObserve && writes {
		return "", fmt.Errorf("a run minted to %s may not carry the write "+
			"tool: the purpose and the tools would disagree, and the gate "+
			"would refuse every write anyway", macaroon.PurposeObserve)
	}
	if level >= 0 {
		// The holder's reach is what the credential itself can do, and a
		// caveat may bound autonomy only within it. This surface tops out
		// at L1 — proposing is the highest autonomy any tool here needs —
		// and a read-only run has nothing above L0 to bound.
		if !writes && level > 0 {
			return "", fmt.Errorf("a run that may not write has no autonomy "+
				"to bound above 0; --level %d is a bound on nothing", level)
		}
		if writes && level > 1 {
			return "", fmt.Errorf("the highest autonomy this surface's tools "+
				"reach is 1 (proposing); --level %d bounds nothing here", level)
		}
	}

	var caveats []macaroon.Caveat
	if tc, err := macaroon.ToolCaveat(tools...); err != nil {
		return "", err
	} else {
		caveats = append(caveats, tc)
	}
	if purpose != "" {
		if pc, err := macaroon.PurposeCaveat(purpose); err != nil {
			return "", err
		} else {
			caveats = append(caveats, pc)
		}
	}
	if level >= 0 {
		if lc, err := macaroon.LevelCaveat(level); err != nil {
			return "", err
		} else {
			caveats = append(caveats, lc)
		}
	}
	caveats = append(caveats,
		macaroon.ExpCaveat(time.Now().UTC().Add(time.Duration(hours)*time.Hour)))
	if calls > 0 {
		if cc, err := macaroon.CallsCaveat(calls); err != nil {
			return "", err
		} else {
			caveats = append(caveats, cc)
		}
	}

	key, err := ensureRunKey(root)
	if err != nil {
		return "", err
	}
	ts, err := loadTokens(root)
	if err != nil {
		return "", err
	}
	// The least role the tools need: viewer reads, analyst proposes — and
	// IssueScoped caps it at the minter's own, so a run token never carries
	// more authority than whoever minted it holds. A no-write run is issued
	// read-only besides, so the credential's coarse bounds and the caveats'
	// fine ones say the same thing on every surface, including the ones
	// that never read the caveats.
	role, scope := auth.RoleViewer, auth.Scope{ReadOnly: true}
	if writes {
		role, scope = auth.RoleAnalyst, auth.Scope{}
	}
	secret, _, err := ts.IssueScoped(agentreg.TokenPrefix+name+"/"+run, name,
		role, "/", time.Duration(hours)*time.Hour, caller.Role, scope)
	if err != nil {
		return "", err
	}
	if err := saveTokens(root, ts); err != nil {
		return "", err
	}
	return macaroon.Mint(secret, key, agentreg.TokenPrefix+name+"/"+run,
		caveats...)
}

// runKeyPath is the store's caveat-minting key: the Ed25519 private key
// every run token's caveats are signed with. It lives beside the registry
// it serves at 0600, written once, because whoever reads it can mint a run
// token with any caveats at all.
func runKeyPath(root string) string { return filepath.Join(root, "agents.key") }

// runPubPath is the run key's public half, which is all a verifier needs.
// The tool gate reads this and never the private half, so a process that
// only checks tokens (an MCP server an agent runs, say) has no reason to be
// able to open the file that mints them.
func runPubPath(root string) string { return filepath.Join(root, "agents.pub") }

// parseRunKey reads a run key file, or explains why what is there cannot
// be one. A wrong-length key is refused rather than padded or truncated:
// a key nobody agrees on is a key every token minted under it will be
// refused by, and the honest time to say so is now.
func parseRunKey(path string, b []byte) (macaroon.MintKey, error) {
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("the run key at %s is %d bytes, not the %d "+
			"an Ed25519 private key is; it is not the key this store minted "+
			"with, so nothing minted as a run token would verify. Move it "+
			"aside and mint again to create a fresh one", path, len(b),
			ed25519.PrivateKeySize)
	}
	return macaroon.MintKey(b), nil
}

// runPub is the public half of a run key, as the verifier must see it.
func runPub(k macaroon.MintKey) macaroon.VerifyKey {
	return k.Public().(ed25519.PublicKey)
}

// ensureRunKey returns the store's run key, creating it — and its public
// half — on first mint. Under the lock beside it, so two mints at once
// cannot each create a key and leave the other's tokens unverifiable. A
// public half that is missing is written again from the private one; a
// public half that disagrees with it is refused, because every token
// minted from here on would fail at the gate.
func ensureRunKey(root string) (macaroon.MintKey, error) {
	path := runKeyPath(root)
	unlock, err := atomicfile.Lock(path + ".lock")
	if err != nil {
		return nil, err
	}
	defer unlock()
	var key macaroon.MintKey
	if b, err := os.ReadFile(path); err == nil {
		if key, err = parseRunKey(path, b); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	} else {
		priv, _, err := macaroon.GenerateMintKey()
		if err != nil {
			return nil, fmt.Errorf("cannot generate a run key pair: %w", err)
		}
		if err := atomicfile.Write(path, priv, 0o600); err != nil {
			return nil, err
		}
		key = priv
	}
	pub := runPub(key)
	switch got, err := os.ReadFile(runPubPath(root)); {
	case os.IsNotExist(err):
		if err := atomicfile.Write(runPubPath(root), pub, 0o644); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	case !bytes.Equal(got, pub):
		return nil, fmt.Errorf("%s is not the public half of %s, so the "+
			"tool gate would refuse every run token minted here; move the "+
			"public file aside and mint again to write it afresh",
			runPubPath(root), path)
	}
	return key, nil
}

// loadRunKey is ensureRunKey's read-only half, for the one other process
// that mints: the token exchange inside serve. An absent key is an error
// rather than an empty one, because "nothing minted as a run token can be
// verified here" is a decision the caller needs to make loudly.
func loadRunKey(root string) (macaroon.MintKey, error) {
	path := runKeyPath(root)
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("there is no run key at %s, so no run token "+
			"can be verified in this store; refusing rather than acting on "+
			"a credential whose caveats nobody can check", path)
	}
	if err != nil {
		return nil, err
	}
	return parseRunKey(path, b)
}

// loadVerifyKey is the verifier's key: the public half only. Absent, it is
// an error for the same reason loadRunKey's is — a gate that cannot check
// caveats refuses the credential rather than waving it through.
func loadVerifyKey(root string) (macaroon.VerifyKey, error) {
	path := runPubPath(root)
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("there is no run verification key at %s, so "+
			"no run token can be verified in this store; refusing rather "+
			"than acting on a credential whose caveats nobody can check", path)
	}
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the run verification key at %s is %d bytes, "+
			"not the %d an Ed25519 public key is", path, len(b),
			ed25519.PublicKeySize)
	}
	return macaroon.VerifyKey(b), nil
}

// agentDisable is the kill switch: responder-grade on purpose, because the
// person who needs to stop an agent at 3am is the one holding the pager,
// not necessarily an administrator.
//
// Two things happen as one act: the registry entry goes disabled, and every
// token bound to the agent is revoked. Either alone is half a switch —
// revoking tokens but leaving the entry active lets somebody issue a fresh
// token that works, and disabling the entry but leaving tokens live leaves
// credentials that fail at the registry rather than at the door. Together
// the bearer dies at the next request and a new one cannot be born until
// somebody enables the entry and the owner asks for a credential.
func agentDisable(root string, caller *Caller, args []string,
	note func(string, string, map[string]string) error) error {

	fs := flag.NewFlagSet("disable", flag.ContinueOnError)
	why := fs.String("why", "", "the reason it was killed, kept on the record")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return agentUsage()
	}
	if strings.TrimSpace(*why) == "" {
		return fmt.Errorf("disabling an agent needs --why: the next person to " +
			"read this register — the review, or whoever decides to enable it " +
			"again — has to know what happened, and \"ask around\" is not a record")
	}
	revoked, err := killAgent(root, caller, pos[0], strings.TrimSpace(*why), note)
	if revoked >= 0 {
		w.Human("%s%s%s is disabled%s\n", bold, pos[0], reset, whySuffix(revoked))
	}
	return err
}

// killAgent is the kill switch itself, the same from the command line and
// the console: the registry entry goes disabled, every token bound to the
// agent is revoked, the act is recorded, and every configured receiver is
// told. It returns how many tokens were revoked, or -1 when the registry
// refused before anything happened.
func killAgent(root string, caller *Caller, name, why string,
	note func(string, string, map[string]string) error) (int, error) {

	if err := agentStore(root).Disable(name, why, caller.Name, time.Now().UTC()); err != nil {
		return -1, err
	}
	revoked, err := revokeAgentTokens(root, name)
	if err != nil {
		// The registry is disabled, which is the half that stops fresh
		// credentials; a failure to reach the token store is reported loudly
		// rather than rolled back, because the tokens that could not be
		// revoked are still refused by the registry gate on their next use.
		return 0, fmt.Errorf("%s is disabled in the registry, but its tokens "+
			"could not be revoked: %v\n  they are refused by the registry "+
			"gate until this is fixed; revoke them by hand with `aertun "+
			"token list` and `aertun token revoke ID`", name, err)
	}
	noteErr := note("agent.disable", name, map[string]string{
		"why": why, "revoked": fmt.Sprintf("%d", revoked)})
	// The outward half of the switch: tell every configured receiver.
	// Best-effort by contract — the local kill has already happened, and a
	// receiver that is unreachable must never be allowed to fail or delay
	// the switch that stops the agent. Each attempt is audited on its own,
	// success or failure, so the record says who heard about the kill and
	// who did not.
	transmitAgentRevocation(root, caller, name, why)
	return revoked, noteErr
}

// transmitAgentRevocation pushes a session-revoked event about one agent to
// every configured SSF receiver (internal/ssf, the transmitter half).
//
// Never returns an error, because nothing here is allowed to change the
// outcome of the kill: with no receivers configured it says transmitting is
// off, and with a receiver that refuses or cannot be reached it says so and
// writes ssf.transmit-failed beside the ssf.transmitted records that did
// succeed. The audit records use record rather than recordE for the same
// reason — a full disk must not fail the kill switch's reporting path.
func transmitAgentRevocation(root string, caller *Caller, agent, why string) {
	cfg := mustConfig(root)
	receivers := ssfReceiverList(cfg)
	if len(receivers) == 0 {
		w.Human("  %stransmitting is off: no receivers are configured, so "+
			"only this store knows%s\n", dim, reset)
		return
	}
	e, err := ssfEmitter(root)
	if err != nil {
		// No key or no issuer. Recorded per receiver rather than once, so
		// the log answers "who was told about this kill" receiver by
		// receiver, which is the question somebody reading it has.
		for _, r := range receivers {
			record(root, caller.auditRecord("ssf.transmit-failed",
				"/agents/"+agent, audit.Failure, map[string]string{
					"receiver": r.URL, "error": err.Error()}))
			w.Human("  %s%s did not hear it: %v%s\n", yellow, r.URL, err, reset)
		}
		return
	}
	secrets, serr := loadSecrets(root)
	if serr != nil {
		secrets = map[string]string{}
	}
	reach := fetch.OnThisNetwork
	if cfg.Bool("ssf.transmit.allow_remote") {
		reach = fetch.Anywhere
	}
	client := fetch.Speaking("signals", reach, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, r := range receivers {
		token, jti, terr := e.SessionRevoked(agent, r.URL, why)
		if terr != nil {
			record(root, caller.auditRecord("ssf.transmit-failed",
				"/agents/"+agent, audit.Failure, map[string]string{
					"receiver": r.URL, "error": terr.Error()}))
			w.Human("  %s%s did not hear it: %v%s\n", yellow, r.URL, terr, reset)
			continue
		}
		bearer := ""
		if r.Secret != "" {
			var ok bool
			if bearer, ok = secrets[r.Secret]; !ok || strings.TrimSpace(bearer) == "" {
				record(root, caller.auditRecord("ssf.transmit-failed",
					"/agents/"+agent, audit.Failure, map[string]string{
						"receiver": r.URL, "jti": jti, "error": "no stored secret " + r.Secret}))
				w.Human("  %s%s did not hear it: no stored secret %q holds "+
					"its token%s\n", yellow, r.URL, r.Secret, reset)
				continue
			}
		}
		if derr := e.Deliver(ctx, client, r.URL, token, bearer); derr != nil {
			record(root, caller.auditRecord("ssf.transmit-failed",
				"/agents/"+agent, audit.Failure, map[string]string{
					"receiver": r.URL, "jti": jti, "error": derr.Error()}))
			w.Human("  %s%s did not hear it: %v%s\n", yellow, r.URL, derr, reset)
			w.Human("    %sthe kill stands here; the audit record says who "+
				"was not told%s\n", dim, reset)
			continue
		}
		record(root, caller.auditRecord("ssf.transmitted", "/agents/"+agent,
			audit.Success, map[string]string{"receiver": r.URL, "jti": jti}))
		w.Human("  %stold %s — session-revoked, id %s%s\n", green, r.URL,
			jti[:8], reset)
	}
}

// agentEnable restores an entry. Deliberately the administrator's act, not
// the responder's: whoever pulled the switch under pressure is exactly who
// should not be able to quietly put it back.
func agentEnable(root string, caller *Caller, args []string,
	note func(string, string, map[string]string) error) error {

	fs := flag.NewFlagSet("enable", flag.ContinueOnError)
	why := fs.String("why", "", "the reason it is being restored, on the record")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return agentUsage()
	}
	if strings.TrimSpace(*why) == "" {
		return fmt.Errorf("enabling an agent needs --why: the register is " +
			"the review, and an entry that switched itself back on with no " +
			"word from anybody is one nobody can trust either way")
	}
	if err := agentStore(root).Enable(pos[0], caller.Name, time.Now().UTC()); err != nil {
		return err
	}
	w.Human("%s%s%s is active again\n", bold, pos[0], reset)
	// Said out loud because it is the honest limit of what was done: the
	// kill revoked the tokens, and enabling the entry does not un-revoke
	// them. That is a feature — a credential that outlived its agent's
	// disablement is a credential nobody had to think about — but only if
	// whoever enabled the entry knows a fresh one must be issued.
	w.Human("  %sits old tokens are still revoked; its owner asks for a fresh one:%s\n", dim, reset)
	w.Human("    aertun token issue %s%s --principal %s --role viewer\n",
		agentreg.TokenPrefix, pos[0], pos[0])
	return note("agent.enable", pos[0], map[string]string{"why": *why})
}

// revokeAgentTokens marks revoked every live token bound to an agent by the
// naming convention, cascading to whatever sessions were minted from them
// (auth.TokenStore.Revoke). Returns how many of the agent's own tokens it
// killed; the cascade is the tokens' business and is not double-counted.
//
// A run token is bound by the same convention with its run after the slash
// (agent:watcher/run-42), and the sweep matches it to watcher: the kill
// switch has to reach a run credential in the same act as the bearer it
// came from, or a run minted just before the switch would outlive it.
//
// Changed on the file as it is stored now, under its lock, so a token
// issued elsewhere since this process read the store is neither missed nor
// resurrected — the same discipline saveTokens holds.
func revokeAgentTokens(root, name string) (int, error) {
	revoked := 0
	err := atomicfile.Update(tokensPath(root), func(stored *auth.TokenStore) error {
		for _, t := range stored.Tokens {
			if t.Revoked {
				continue
			}
			bound, ok := agentreg.Bind(t.Name)
			if ok {
				// Strip the run, if the name carries one: the agent the
				// credential belongs to is the half before the slash.
				if agent, _, split := splitAgentRun(bound); split {
					bound = agent
				}
			}
			if !ok || bound != name {
				continue
			}
			if _, err := stored.Revoke(t.ID); err != nil {
				return err
			}
			revoked++
		}
		return nil
	})
	return revoked, err
}

func whySuffix(revoked int) string {
	if revoked == 0 {
		return " (it held no live tokens)"
	}
	return fmt.Sprintf(" — and its %d live token(s) are revoked, so the bearers die at the next request", revoked)
}

// agentConsents is the consent register's read-and-end surface: what the
// authorization server recorded when people answered their agents' asks
// (internal/oauthas), listed for review, revoked one at a time.
//
// Revoking a consent is the delegation half of the kill switch's shape: the
// register row dies and every token minted under it — the consented access
// token and every on-behalf-of credential exchanged from it — dies with it,
// in the same act, because a consent that outlived its revocation would be
// a consent the register lied about.
func agentConsents(root string, caller *Caller, args []string,
	note func(string, string, map[string]string) error) error {

	if len(args) == 0 {
		return agentConsentsList(root)
	}
	if args[0] != "revoke" || len(args) != 2 {
		return agentUsage()
	}
	id := args[1]
	c, err := consentStore(root).Revoke(id, caller.Name, time.Now().UTC())
	if err != nil {
		return err
	}
	toks, err := loadTokens(root)
	if err != nil {
		// The register is revoked, which is the half that stops fresh
		// tokens; the tokens that could not be reached are refused at
		// their next exchange by the register itself, so the failure is
		// reported loudly rather than rolled back — the same line the
		// agent kill switch takes.
		return fmt.Errorf("consent %s is revoked, but its tokens could not "+
			"be: %v\n  they are refused at the next exchange regardless; "+
			"`aertun token list` shows what is still live", id, err)
	}
	killed := toks.RevokeGrant(id)
	if err := saveTokens(root, toks); err != nil {
		return err
	}
	w.Human("%s%s%s revoked — it was agent %s acting for %s (%s)%s\n", bold, id,
		reset, c.Agent, c.Principal, c.Scope, whySuffix(killed))
	return note("consent.revoke", c.Agent, map[string]string{
		"grant": id, "scope": c.Scope, "revoked": fmt.Sprintf("%d", killed)})
}

// agentConsentsList prints the register: live consents first, then the
// ended, newest of each first — the review's question is who may what now.
func agentConsentsList(root string) error {
	all, err := consentStore(root).Load()
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"consents": all}) {
		return nil
	}
	live := oauthas.Sorted(all)
	if len(live) == 0 {
		w.Human("  no agent has been consented to; nothing has been delegated\n")
		w.Human("  %sa consent is made where the authorization server asks: an agent's \"authorize\" request, answered in the console%s\n", dim, reset)
		return nil
	}
	for _, c := range live {
		word, until := "live", "until "+c.Until()
		colour := green
		if c.Revoked {
			word, until, colour = "revoked", "revoked by "+c.RevokedBy, red
		} else if time.Now().UTC().Unix() >= c.ExpiresAt {
			word, colour = "ended", dim
		}
		w.Human("  %s%s%s  %s%s%s  agent %s  for %s  %s\n", bold, c.ID, reset,
			colour, word, reset, c.Agent, c.Principal, c.Scope)
		w.Human("    %s%s, given %s%s\n", colour, until,
			c.CreatedAt.Format("2 Jan 2006 15:04"), reset)
	}
	w.Human("\n  %sa consent is one of the three bounds on an exchanged token; end one with \"aertun agent consents revoke ID\"%s\n", dim, reset)
	return nil
}

func agentHelp() error {
	w.Human(`  Agents are registered before they act, and can be stopped as one act.

  An agent is a principal of its own: a token issued as agent:NAME binds to
  a registry entry, and every gate — the policy check included — refuses
  that token unless the entry exists, is active, and lists the tool being
  called in its allowlist. An unregistered agent is nobody.

  aertun agent add watcher --owner dana@acme.example --allow aertun_read
  aertun token issue agent:watcher --principal watcher --role viewer
  The register decides who the agent is; the token is its credential, and
  the owner asks for a fresh one whenever it needs one.

  aertun agent list                     who is registered, what each may call
  aertun agent allow watcher --add aertun_write
  aertun agent allow watcher --remove aertun_read

  Where each agent runs
  aertun agent maps watcher --host build01
  A declaration, not a guess: the collector's evidence says a file changed
  on a host and never who changed it, and an operator who knows the estate
  is the one who can say which agents run there. Once said, every watch and
  heartbeat event from that host carries the declared names (raw.agents),
  so a config change can be joined to the agent whose config it was. A host
  maps to at most four agents — a shared CI box is a fact, a mapping that
  grows past it is an inference nobody wrote — and the names must be
  registered here. --remove takes the declaration back; a change shows up
  on the host's next push, never in the events already stored.

  Bounding one run
  aertun agent token watcher --tools aertun_read --for-run triage-2026-10-27
  A run token is a credential whose caveats narrow it to one run: the tools
  it may call (within what the register allows the agent), a deadline, a
  purpose, a call budget, an autonomy bound. Its credential half is issued
  by the same machinery as any token, so revoking it, disabling the agent
  and the kill switch all reach it; its caveat half is signed by a key held
  by this store, so nobody who holds it can widen it — only narrow it
  further. It is checked where its tools are called; present it with
  --token like any credential, and expect the bare half of it to be
  refused on its own, because the caveats are the credential.

  The kill switch
  aertun agent disable watcher --why "proposing nonsense on closed findings"
  This is a responder's act, deliberately: the person who needs to stop an
  agent is the one holding the pager. It disables the entry and revokes the
  agent's tokens in the same action, so the bearers die at the next request
  rather than at the next registry check. Enabling the entry back is an
  administrator's act with a reason; the old tokens stay dead either way.

  When receivers are configured (aertun ssf receivers says who), the same
  act tells them: a signed session-revoked event reaches every one of them,
  best-effort, so a platform that trusted the agent kills its sessions too.
  A receiver that is down is recorded as not hearing it and the kill here
  stands regardless — the switch must work offline.

  What people have consented to
  aertun agent consents
  When an agent asks to act for somebody over the authorization server
  (/oauth/authorize, mounted beside the console), the person answers in
  their browser and the answer is a row in a register: who authorised which
  agent for which scope bundle — observe (reads) or triage (reads and
  proposals) — until when, twelve hours at most. The row outlives the
  click; it is the durable half of a delegation, and this lists it.
  aertun agent consents revoke ID ends one, and every token minted under
  it dies in the same act: the consented access token and every
  on-behalf-of credential an agent exchanged from it. An exchange itself is
  bounded three ways — the consent's bundle, the registry's allowlist, and
  the credential the agent presented — and the narrowest of the three is
  what the exchanged token carries.

  There is deliberately no "disable all agents" here. A switch that turns
  off every agent at once is an availability weapon — one command, every
  responder's helper gone — and it waits on dual control until that is
  built. Agents are killed
  one at a time, by name, on the record.
`)
	return nil
}
