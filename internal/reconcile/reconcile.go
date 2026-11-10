// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package reconcile holds an AI agent's own account of what it did against
// what was seen independently of it.
//
// # Why
//
// An agent's telemetry — the GenAI spans its SDK emits — is the agent's
// word about itself. Guidance on running agents asks that agent reports be
// cross-validated against system logs, because an agent that was steered, or
// built to hide what it does, reports what it likes; deleting one's own
// traces is a technique of its own in the attack matrices. This program
// already hears two things the agent does not write: every call the agent
// makes to this program's agent interface, recorded by the server that
// answered it, and the connections the recorder sees leave a machine the
// agent runs on. Reconciling is holding the first against the second.
//
// # What is matched, and on what
//
// Only on what the evidence carries, never on a guess:
//
//   - A call the agent interface answered is matched to a span the agent
//     reported for the same tool of that interface within Window, each span
//     used once, nearest first. A host prefixes a server's tools in its own
//     way (mcp__aertun__aertun_read, aertun.aertun_read), so a span's tool
//     matches when it is the tool's name or ends in it after one of the
//     separators hosts use; nothing looser.
//   - A span for a tool of this agent interface that no call matches is a
//     call the agent says it made and the server never received.
//   - A connection from a machine the operator declared runs this agent and
//     no other is matched to any span the agent reported within Window of
//     it. A machine declared for several agents is counted and skipped:
//     whose connection it was is not in the evidence.
//
// What is not matched is listed, by time and by names from closed sets or
// strict shapes, never by anything the agent wrote.
package reconcile

import (
	"net"

	"github.com/aertun/aertun/internal/proof"
	"sort"
	"strings"
	"time"
)

// Tools are the agent interface's own tools: every call to one of them
// reaches this program's server, and is recorded there. The proof names the
// same set, so a tool this package matches is one a proof may name.
var Tools = proof.InterfaceTools

// MaxListed is how many unexplained items of each kind a result names.
const MaxListed = 50

// Span is one tool call the agent reported.
type Span struct {
	At   time.Time
	Tool string
}

// Call is one call the agent interface answered for the agent.
type Call struct {
	At   time.Time
	Tool string
}

// Connect is one connection the recorder saw leave a machine.
type Connect struct {
	At   time.Time
	Host string
	Addr string
	Port string
}

// Input is everything one reconciliation reads.
type Input struct {
	Since, Until time.Time
	Window       time.Duration
	Spans        []Span
	Calls        []Call
	Connects     []Connect
	// Hosts are the machines declared to run this agent and no other;
	// Shared those declared to run it beside others.
	Hosts, Shared []string
}

// Result is what came of it.
type Result struct {
	// Reported is the agent's spans in the period; ForInterface those for a
	// tool of the agent interface.
	Reported, ForInterface int
	// Calls is the agent interface's calls for it in the period, Matched
	// those its spans account for.
	Calls, Matched int
	// Unreported are the calls no span accounts for; Unreceived the spans
	// for the agent interface no call matches.
	Unreported []Call
	Unreceived []Span
	// Connects is the connections from its own machines in the period, and
	// Unexplained those with no span of the agent near them. SharedSkipped
	// is connections from machines it shares, which nothing here can
	// attribute.
	Connects, SharedSkipped int
	Unexplained             []Connect
}

// interfaceTool is the agent-interface tool a span's tool names, or "".
func interfaceTool(s string) string {
	for _, t := range Tools {
		if s == t {
			return t
		}
		for _, sep := range []string{"__", ".", "/", ":"} {
			if strings.HasSuffix(s, sep+t) {
				return t
			}
		}
	}
	return ""
}

// exactTool reports whether s is one of the interface's tools, as the server
// names them.
func exactTool(s string) bool {
	for _, t := range Tools {
		if s == t {
			return true
		}
	}
	return false
}

func within(a, b time.Time, w time.Duration) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d <= w
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// ValidAddr reports whether a destination is an address and a port, the
// only shape a connection is named in.
func ValidAddr(addr, port string) bool {
	if net.ParseIP(addr) == nil {
		return false
	}
	if len(port) == 0 || len(port) > 5 {
		return false
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Reconcile holds the spans against the calls and the connections.
func Reconcile(in Input) Result {
	inPeriod := func(t time.Time) bool { return !t.Before(in.Since) && t.Before(in.Until) }
	var r Result

	// Spans are read a window either side of the period, so a call at its
	// edge can be matched to a span just outside it; only those inside are
	// counted as reported.
	var spans []Span
	for _, s := range in.Spans {
		if s.At.Before(in.Since.Add(-in.Window)) || !s.At.Before(in.Until.Add(in.Window)) {
			continue
		}
		spans = append(spans, s)
		if inPeriod(s.At) {
			r.Reported++
		}
	}
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].At.Before(spans[j].At) })

	// Calls to the agent interface, each matched to the nearest unused span
	// for the same tool within the window.
	used := make([]bool, len(spans))
	var calls []Call
	for _, c := range in.Calls {
		// Exactly the interface's names: the server knows its own tools, and
		// a call naming anything else — which a client may send, and which is
		// refused and recorded under the name it gave — is not one of them.
		if inPeriod(c.At) && exactTool(c.Tool) {
			calls = append(calls, c)
		}
	}
	sort.SliceStable(calls, func(i, j int) bool { return calls[i].At.Before(calls[j].At) })
	r.Calls = len(calls)
	for _, c := range calls {
		best := -1
		for i, s := range spans {
			if used[i] || interfaceTool(s.Tool) != c.Tool || !within(s.At, c.At, in.Window) {
				continue
			}
			if best < 0 || abs(s.At.Sub(c.At)) < abs(spans[best].At.Sub(c.At)) {
				best = i
			}
		}
		if best >= 0 {
			used[best] = true
			r.Matched++
		} else {
			r.Unreported = append(r.Unreported, c)
		}
	}
	for i, s := range spans {
		t := interfaceTool(s.Tool)
		if t == "" || !inPeriod(s.At) {
			continue
		}
		r.ForInterface++
		if !used[i] {
			r.Unreceived = append(r.Unreceived, Span{At: s.At, Tool: t})
		}
	}

	// Connections from its own machines, each explained by any span of the
	// agent near it: the span says it was acting, not what it connected to,
	// which no span carries.
	own, shared := map[string]bool{}, map[string]bool{}
	for _, h := range in.Hosts {
		own[h] = true
	}
	for _, h := range in.Shared {
		shared[h] = true
	}
	var conns []Connect
	for _, c := range in.Connects {
		if !inPeriod(c.At) {
			continue
		}
		switch {
		case shared[c.Host]:
			r.SharedSkipped++
		case own[c.Host] && ValidAddr(c.Addr, c.Port):
			conns = append(conns, c)
		}
	}
	sort.SliceStable(conns, func(i, j int) bool { return conns[i].At.Before(conns[j].At) })
	r.Connects = len(conns)
	for _, c := range conns {
		near := false
		for _, s := range spans {
			if within(s.At, c.At, in.Window) {
				near = true
				break
			}
		}
		if !near {
			r.Unexplained = append(r.Unexplained, c)
		}
	}
	return r
}
