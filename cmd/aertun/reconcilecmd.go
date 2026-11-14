// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/reconcile"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// `aertun agent reconcile NAME`: a registered agent's own account of what it
// did, held against what this program saw it do without asking it, signed as
// a reconciliation proof (internal/proof) and kept where the proving ground
// shows it.
//
// The agent's account is its GenAI telemetry: the tool calls its SDK
// reported over OTLP, under the identity it reports itself by. What was seen
// without it is two things this program records itself. Every call to the
// agent interface is in the signed audit log, under the calling token's
// name, which for a registered agent is agent:NAME; the log is verified
// before anything is read from it. And every connection the recorder saw
// leave a machine the operator declared runs this agent (aertun agent maps)
// is in the event store. Nothing is joined on anything the evidence does not
// carry: a machine declared for several agents is counted and left out,
// because whose connection it was is not in the evidence.

// reconcileRead bounds how far a reconciliation reads: a period longer than
// this is several reconciliations.
const reconcileRead = 31 * 24 * time.Hour

const (
	otelSource   = "otel/genai"
	auditdSource = "auditd/events"
)

func agentReconcile(root string, caller *Caller, args []string) error {
	fs := flag.NewFlagSet("agent reconcile", flag.ContinueOnError)
	sinceAt := fs.String("since", "", "the period's start: a date or an RFC 3339 time")
	untilAt := fs.String("until", "", "the period's end, not included (default: now)")
	window := fs.Duration("window", 2*time.Minute, "how far apart a call and the agent's report "+
		"of it may be, for clocks and queues: between 1s and 1h")
	telemetryID := fs.String("telemetry", "", "the identity the agent's GenAI spans name it by "+
		"(gen_ai.agent.id), as you declare it (default: its registered name)")
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	var name string
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		name, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if name == "" || fs.NArg() != 0 || *sinceAt == "" || *keyAt == "" {
		return fmt.Errorf("agent reconcile takes NAME --since DATE --key FILE: an unsigned " +
			"reconciliation is a claim about a claim")
	}
	if *window < time.Second || *window > time.Hour {
		return fmt.Errorf("--window is between 1s and 1h")
	}
	tele := *telemetryID
	if tele == "" {
		tele = name
	}
	now := time.Now().UTC()
	since, err := parseDay(*sinceAt)
	if err != nil {
		return err
	}
	until := now
	if *untilAt != "" {
		if until, err = parseDay(*untilAt); err != nil {
			return err
		}
	}
	if !since.Before(until) || until.After(now) || until.Sub(since) > reconcileRead {
		return fmt.Errorf("the period starts before it ends, does not end in the future, "+
			"and is at most %d days", int(reconcileRead.Hours()/24))
	}
	// Tune, like the other proofs signed from the store: a signed account
	// of an agent in this organisation's name is one somebody acts on.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	if _, ok, err := agentStore(root).Get(name); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("no agent %q is registered: an account is held against a registered "+
			"agent, so whose it is is not a guess (aertun agent add)", name)
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}

	// The machines declared to run it: alone, or beside other agents.
	maps, err := agentMapStore(root).Load()
	if err != nil {
		return err
	}
	var own, shared []string
	for _, m := range maps {
		mine := false
		for _, a := range m.Agents {
			mine = mine || a == name
		}
		switch {
		case !mine:
		case len(m.Agents) == 1 && proof.ValidHost(m.Host):
			own = append(own, m.Host)
		default:
			shared = append(shared, m.Host)
		}
	}

	// The calls the agent interface answered for it, from the verified log.
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	if ok, problems := audit.Verify(events); !ok {
		p := problems[0]
		return fmt.Errorf("the audit log does not verify, so nothing can be taken from it: "+
			"entry %d: %s", p.Seq, p.Reason)
	}
	var lines bytes.Buffer
	line := func(v any) {
		b, _ := json.Marshal(v)
		lines.Write(b)
		lines.WriteByte('\n')
	}
	in := reconcile.Input{Since: since, Until: until, Window: *window, Hosts: own, Shared: shared}
	for _, e := range events {
		// By the registered name the gate checked, not by the client: that
		// is the principal a credential was issued to, which need not be the
		// agent's name.
		if e.Action != "mcp.call" || e.Detail["agent"] != name {
			continue
		}
		at, perr := time.Parse(time.RFC3339Nano, e.At)
		if perr != nil || at.Before(since) || !at.Before(until) {
			continue
		}
		in.Calls = append(in.Calls, reconcile.Call{At: at, Tool: e.Detail["tool"]})
		line(map[string]any{"call": e.Detail["tool"], "at": at, "seq": e.Seq})
	}

	// Its own account, and the connections from its machines, from the
	// event store: read a window either side, so a call at the period's edge
	// can meet its report.
	machines := map[string]bool{}
	for _, h := range append(append([]string{}, own...), shared...) {
		machines[h] = true
	}
	if _, err := os.Stat(spoolDir(root)); err == nil {
		sp, err := openSpool(root, spool.Options{})
		if err != nil {
			return err
		}
		defer sp.Close()
		err = sp.Range(since.Add(-*window), until.Add(*window), func(e telemetry.Event) error {
			switch {
			case e.Source == otelSource && e.Actor.Value == tele && e.Raw["operation"] == "execute_tool":
				in.Spans = append(in.Spans, reconcile.Span{At: e.Time, Tool: e.Raw["tool"]})
				line(map[string]any{"span": e.Raw["tool"], "at": e.Time})
			case e.Source == auditdSource && e.Raw["syscall"] == "connect" && machines[e.Device.Value]:
				in.Connects = append(in.Connects, reconcile.Connect{At: e.Time, Host: e.Device.Value,
					Addr: e.Raw["addr"], Port: e.Raw["port"]})
				line(map[string]any{"connect": e.Device.Value, "at": e.Time})
			}
			return nil
		})
		if err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if lines.Len() == 0 {
		// Nothing read at all is still something to sign: it says the agent
		// neither reported nor was seen. The digest is over that fact.
		line(map[string]any{"read": "nothing", "since": since, "until": until})
	}

	r := reconcile.Reconcile(in)
	pin := proof.ReconciliationInput{Agent: name, Telemetry: tele, Since: since, Until: until,
		Window: *window, Lines: lines.Bytes(), Reported: r.Reported, ForInterface: r.ForInterface,
		Calls: r.Calls, Matched: r.Matched, Hosts: own, SharedHosts: len(shared),
		Connects: r.Connects, SharedSkipped: r.SharedSkipped, Program: version, Now: now}
	for _, c := range r.Unreported {
		pin.Unreported = append(pin.Unreported, proof.AgentCall{Tool: c.Tool, At: c.At})
	}
	for _, c := range r.Unreceived {
		pin.Unreceived = append(pin.Unreceived, proof.AgentCall{Tool: c.Tool, At: c.At})
	}
	for _, c := range r.Unexplained {
		pin.Unexplained = append(pin.Unexplained, proof.AgentConnect{Host: c.Host, Addr: c.Addr,
			Port: c.Port, At: c.At})
	}
	if len(events) > 0 {
		head := events[len(events)-1]
		pin.Materials = append(pin.Materials, proof.Material{Name: "audit-log",
			Digest: proof.Digest{"sha256": head.Hash}, Entries: len(events)})
	}
	for _, f := range []struct{ name, path string }{{"agent-register", agentsPath(root)},
		{"agent-hosts", agentMapsPath(root)}} {
		if b, err := os.ReadFile(f.path); err == nil {
			pin.Materials = append(pin.Materials, proof.Material{Name: f.name, Digest: proof.SHA256(b)})
		}
	}
	st, err := proof.ProveReconciliation(pin)
	if err != nil {
		return err
	}
	env, err := proof.Seal(st, k)
	if err != nil {
		return err
	}
	doc, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	doc = append(doc, '\n')
	if *pubAt != "" {
		if err := pack.WritePublicKey(*pubAt, k.PublicKey()); err != nil {
			return err
		}
	}
	if pubDoc, err := json.Marshal(k.PublicKey()); err == nil {
		keepMade(root, env, pubDoc, caller.Name)
	}
	ev := st.Predicate.Reconciliation
	if err := recordE(root, caller.auditRecord("agent.reconciled", "/agents/"+name, audit.Success,
		map[string]string{"agent": name, "verdict": string(st.Predicate.Verdict),
			"calls": fmt.Sprint(ev.Calls), "unreported": fmt.Sprint(ev.Unreported),
			"unreceived": fmt.Sprint(ev.Unreceived), "unexplained": fmt.Sprint(ev.Unexplained),
			"since": ev.Since, "until": ev.Until})); err != nil {
		return err
	}
	if *outAt == "" {
		if _, err := os.Stdout.Write(doc); err != nil {
			return err
		}
	} else {
		if err := atomicfile.Write(*outAt, doc, 0o600); err != nil {
			return err
		}
		if !w.JSON(summary(st)) {
			w.Human("%s\n", describe(st))
		}
	}
	return notProven(st)
}
