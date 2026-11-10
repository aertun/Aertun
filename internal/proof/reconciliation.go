// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// A reconciliation proof: an AI agent's own account of what it did, held
// against what this program saw it do without asking it (internal/reconcile).
//
// # The claim
//
// Over a declared period, everything seen independently — every call the
// agent interface answered for the agent, recorded in this program's signed
// audit log, and every connection the recorder saw leave a machine the
// operator declared runs this agent and no other — is in the agent's own
// telemetry, and nothing that telemetry says it asked of the agent interface
// went unreceived.
//
//   - refuted when anything is unaccounted for either way, and the proof
//     names each by time and by names from closed sets or strict shapes. An
//     agent that reported nothing while it was seen acting is refuted too:
//     the claim is that its account covers what it did, and an empty account
//     covers nothing. The proof says that it cannot tell an agent never
//     instrumented from one that went quiet — the claim is false either way,
//     and which of the two it was is for whoever reads it to find out;
//   - proven when nothing is, over at least MinObserved independent
//     observations;
//   - inconclusive when there were fewer, and nothing could fail.
//
// # What it does not cover
//
// What the agent did elsewhere — in a repository, a cloud account, a SaaS
// tool — is not in it: nothing here ties an agent to its identity in those
// systems, and joining on a guess would put one agent's actions on
// another's record. A connection says the agent's machine reached an
// address while the agent reported nothing near it, not what was sent.

// ReconciliationVerifier and its version name this verifier.
const (
	ReconciliationVerifier        = "aertun/reconcile"
	ReconciliationVerifierVersion = "1"
)

// PredicateReconciliation is the predicate of a reconciliation proof.
const PredicateReconciliation = "https://aertun.github.io/proof/reconciliation/v1"

// MinObserved is the fewest independent observations a proven verdict may
// rest on: below it, an agent that did almost nothing would be proven to have
// reported almost everything.
const MinObserved = 10

// InterfaceTools are the agent interface's own tools: every call to one of
// them reaches this program's server and its audit log.
var InterfaceTools = []string{"aertun_find", "aertun_read", "aertun_write"}

func interfaceToolName(s string) bool { return containsString(InterfaceTools, s) }

// ValidHost reports whether a machine's name can be carried in a
// reconciliation: letters, digits, dots, hyphens and underscores. A machine
// declared under any other name is counted as one nothing can be attributed
// to, never written into a proof.
func ValidHost(s string) bool { return hostShape.MatchString(s) }

func containsString(set []string, s string) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

// AgentCall is a call to the agent interface, named by its tool and time.
type AgentCall struct {
	Tool string
	At   time.Time
}

// AgentConnect is a connection from an agent's machine, named by the
// machine, the destination and the time.
type AgentConnect struct {
	Host, Addr, Port string
	At               time.Time
}

// ReconciliationEvidence is what the agent reported and what was seen, as
// counts.
type ReconciliationEvidence struct {
	// Agent is the registered agent; Telemetry the identity its spans name
	// it by, as the operator declared.
	Agent     string `json:"agent"`
	Telemetry string `json:"telemetry_agent"`
	Since     string `json:"since"`
	Until     string `json:"until"`
	Window    int    `json:"window_seconds"`
	// Reported is the agent's own tool-call spans in the period, and
	// ForInterface those for a tool of the agent interface.
	Reported     int `json:"reported"`
	ForInterface int `json:"for_interface"`
	// Calls is the agent interface's calls for it in the period; Matched
	// those its spans account for, Unreported those they do not, and
	// Unreceived its spans for the interface no call matches.
	Calls      int `json:"calls"`
	Matched    int `json:"matched"`
	Unreported int `json:"unreported"`
	Unreceived int `json:"unreceived"`
	// Hosts are the machines declared to run it alone, and SharedHosts how
	// many it shares; Connects the connections from its own, Unexplained
	// those with no span of it near, SharedSkipped those from shared ones.
	Hosts         []string `json:"hosts"`
	SharedHosts   int      `json:"shared_hosts"`
	Connects      int      `json:"connects"`
	Unexplained   int      `json:"unexplained"`
	SharedSkipped int      `json:"shared_skipped"`
	MinObserved   int      `json:"min_observed"`
}

// ReconciliationInput is what a reconciliation proof is made from.
type ReconciliationInput struct {
	Agent, Telemetry string
	Since, Until     time.Time
	Window           time.Duration
	// Lines are the spans, calls and connections read, one JSON object per
	// line, in the order they were read: what the subject's digest is over.
	Lines []byte

	Reported, ForInterface, Calls, Matched int
	Unreported                             []AgentCall
	Unreceived                             []AgentCall
	Hosts                                  []string
	SharedHosts, Connects, SharedSkipped   int
	Unexplained                            []AgentConnect

	Materials []Material
	Program   string
	Now       time.Time
}

var (
	// The registry's own shape for an agent's name (agentreg.ValidName).
	agentShape = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,39}$`)
	identShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$`)
	hostShape  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)
)

func callFailure(kind string, c AgentCall) string {
	return kind + ": " + c.Tool + " at " + c.At.UTC().Format(time.RFC3339Nano)
}

func connectFailure(c AgentConnect) string {
	return "unexplained connection: " + c.Host + " to " + net.JoinHostPort(c.Addr, c.Port) +
		" at " + c.At.UTC().Format(time.RFC3339Nano)
}

const (
	unreportedPhrase = "unreported call"
	unreceivedPhrase = "claimed, never received"
)

// validCallFailure and validConnectFailure accept only the shapes the two
// functions above write: closed phrases, closed tool names, strict hosts and
// addresses, and times.
func validCallFailure(phrase, s string) bool {
	rest, ok := strings.CutPrefix(s, phrase+": ")
	if !ok {
		return false
	}
	tool, when, ok := strings.Cut(rest, " at ")
	if !ok || !interfaceToolName(tool) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, when)
	return err == nil
}

func validConnectFailure(s string) bool {
	rest, ok := strings.CutPrefix(s, "unexplained connection: ")
	if !ok {
		return false
	}
	host, rest, ok := strings.Cut(rest, " to ")
	if !ok || !hostShape.MatchString(host) {
		return false
	}
	dest, when, ok := strings.Cut(rest, " at ")
	if !ok {
		return false
	}
	addr, port, err := net.SplitHostPort(dest)
	if err != nil || net.ParseIP(addr) == nil {
		return false
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return false
	}
	_, err = time.Parse(time.RFC3339Nano, when)
	return err == nil
}

// ProveReconciliation builds the unsigned statement.
func ProveReconciliation(in ReconciliationInput) (*Statement, error) {
	if !agentShape.MatchString(in.Agent) || !identShape.MatchString(in.Telemetry) ||
		!in.Since.Before(in.Until) || in.Window <= 0 || in.Window > time.Hour {
		return nil, fmt.Errorf("a reconciliation names a registered agent, the identity its " +
			"telemetry uses, a period, and a window between a second and an hour")
	}
	if len(in.Lines) == 0 {
		return nil, fmt.Errorf("nothing was read for the period, so there is nothing to reconcile")
	}
	ev := &ReconciliationEvidence{Agent: in.Agent, Telemetry: in.Telemetry,
		Since: day(in.Since), Until: day(in.Until), Window: int(in.Window / time.Second),
		Reported: in.Reported, ForInterface: in.ForInterface, Calls: in.Calls, Matched: in.Matched,
		Unreported: len(in.Unreported), Unreceived: len(in.Unreceived),
		Hosts: append([]string{}, in.Hosts...), SharedHosts: in.SharedHosts,
		Connects: in.Connects, Unexplained: len(in.Unexplained), SharedSkipped: in.SharedSkipped,
		MinObserved: MinObserved}
	var unreported, unreceived, unexplained []string
	for _, c := range in.Unreported {
		unreported = append(unreported, callFailure(unreportedPhrase, c))
	}
	for _, c := range in.Unreceived {
		unreceived = append(unreceived, callFailure(unreceivedPhrase, c))
	}
	for _, c := range in.Unexplained {
		unexplained = append(unexplained, connectFailure(c))
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "agent/" + in.Agent, Digest: SHA256(in.Lines)}},
		PredicateType: PredicateReconciliation,
		Predicate: Predicate{
			Claim:   ev.claim(),
			Verdict: ev.verdict(),
			Verifier: VerifierID{ID: ReconciliationVerifier, Version: ReconciliationVerifierVersion,
				Program: in.Program},
			Materials:      append([]Material{}, in.Materials...),
			Checks:         ev.checks(unreported, unreceived, unexplained),
			Reconciliation: ev, VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	// The whole statement, as Seal will check it: a verdict that disagrees
	// with its checks is caught here, not when somebody tries to sign it.
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *ReconciliationEvidence) observed() int { return ev.Calls + ev.Connects }

func (ev *ReconciliationEvidence) claim() string {
	return fmt.Sprintf("Between %s and %s, every call this program's agent interface answered "+
		"for agent %s, and every connection from a machine declared to run it alone, is in the "+
		"agent's own telemetry as %s, and nothing that telemetry says it asked of the agent "+
		"interface went unreceived.", ev.Since, ev.Until, ev.Agent, ev.Telemetry)
}

func (ev *ReconciliationEvidence) verdict() Verdict {
	switch {
	case ev.Unreported+ev.Unreceived+ev.Unexplained > 0:
		return Refuted
	case ev.Reported > 0 && ev.observed() >= MinObserved:
		return Proven
	}
	return Inconclusive
}

// checks are the proof's checks, from the evidence and the names of what was
// not accounted for: each lists at most MaxFailures and counts the rest.
func (ev *ReconciliationEvidence) checks(unreported, unreceived, unexplained []string) []Check {
	// What the account held, said as it is: the checks below are where it
	// passes or fails.
	reported := Check{Name: "reported", Passed: true,
		Detail: fmt.Sprintf("the agent's own telemetry reported %d tool call(s) in the period, "+
			"%d of them to the agent interface; %d observation(s) were made without it",
			ev.Reported, ev.ForInterface, ev.observed())}
	if ev.Reported == 0 && ev.observed() > 0 {
		reported.Detail += "; it reported nothing while it was seen acting, which nothing here " +
			"tells apart from never having been instrumented"
	} else if ev.observed() < MinObserved && ev.verdict() != Refuted {
		reported.Detail += fmt.Sprintf("; fewer than the %d a proven verdict needs", MinObserved)
	}
	calls := Check{Name: "calls-accounted-for", Passed: ev.Unreported+ev.Unreceived == 0,
		Detail: fmt.Sprintf("%d of the %d call(s) the agent interface answered for it are in "+
			"its own account, within %d second(s); %d are not; %d call(s) it reports were "+
			"never received", ev.Matched, ev.Calls, ev.Window, ev.Unreported, ev.Unreceived)}
	failures := append(append([]string{}, unreported...), unreceived...)
	shown, more := capped(failures)
	calls.Failures = shown
	if more > 0 {
		calls.Detail += fmt.Sprintf("; %d more not listed", more)
	}
	conns := Check{Name: "connections-accounted-for", Passed: ev.Unexplained == 0,
		Detail: fmt.Sprintf("%d connection(s) from %d machine(s) declared to run it alone; "+
			"%d while it reported nothing within %d second(s); %d from %d machine(s) it "+
			"shares were not attributed", ev.Connects, len(ev.Hosts), ev.Unexplained, ev.Window,
			ev.SharedSkipped, ev.SharedHosts)}
	shown, more = capped(unexplained)
	conns.Failures = shown
	if more > 0 {
		conns.Detail += fmt.Sprintf("; %d more not listed", more)
	}
	return []Check{reported, calls, conns}
}

// validate refuses evidence whose numbers do not add up, do not support the
// verdict, or do not account for every word the statement says.
func (ev *ReconciliationEvidence) validate(s *Statement) error {
	if !agentShape.MatchString(ev.Agent) || !identShape.MatchString(ev.Telemetry) ||
		!validPeriod(ev.Since, ev.Until) || ev.Window <= 0 || ev.Window > 3600 {
		return fmt.Errorf("the reconciliation does not name an agent, its telemetry, a period and a window")
	}
	for _, h := range ev.Hosts {
		if !hostShape.MatchString(h) {
			return fmt.Errorf("a machine in a reconciliation is named by its host and nothing else")
		}
	}
	nonneg := ev.Reported >= 0 && ev.ForInterface >= 0 && ev.Calls >= 0 && ev.Matched >= 0 &&
		ev.Unreported >= 0 && ev.Unreceived >= 0 && ev.SharedHosts >= 0 && ev.Connects >= 0 &&
		ev.Unexplained >= 0 && ev.SharedSkipped >= 0
	if !nonneg || ev.Matched+ev.Unreported != ev.Calls || ev.ForInterface > ev.Reported ||
		ev.Unreceived > ev.ForInterface || ev.Unexplained > ev.Connects {
		return fmt.Errorf("the reconciliation's counts do not add up")
	}
	if ev.MinObserved != MinObserved {
		return fmt.Errorf("the evidence's minimum is not this version's")
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("the counts make this %s, not %s", want, s.Predicate.Verdict)
	}
	if len(s.Predicate.Checks) != 3 {
		return fmt.Errorf("a reconciliation has three checks")
	}
	var unreported, unreceived, unexplained []string
	for i, c := range s.Predicate.Checks {
		for _, f := range c.Failures {
			switch {
			case i == 1 && validCallFailure(unreportedPhrase, f):
				unreported = append(unreported, f)
			case i == 1 && validCallFailure(unreceivedPhrase, f):
				unreceived = append(unreceived, f)
			case i == 2 && validConnectFailure(f):
				unexplained = append(unexplained, f)
			default:
				return fmt.Errorf("a failure in a reconciliation names a call or a connection " +
					"in its own shape, on its own check, and nothing else")
			}
		}
	}
	if len(unreported)+len(unreceived) != min(ev.Unreported+ev.Unreceived, MaxFailures) ||
		len(unexplained) != min(ev.Unexplained, MaxFailures) ||
		(ev.Unreported+ev.Unreceived <= MaxFailures &&
			(len(unreported) != ev.Unreported || len(unreceived) != ev.Unreceived)) {
		return fmt.Errorf("the failures listed are not the ones counted")
	}
	// Padded to the counts, so the rebuilt checks say the same "more not
	// listed" the statement does.
	pad := func(list []string, n int) []string { return append(list, make([]string, n-len(list))...) }
	callNames := pad(append(unreported, unreceived...), ev.Unreported+ev.Unreceived)
	return sameWords(s, "agent/"+ev.Agent, ev.claim(),
		ev.checks(callNames, nil, pad(unexplained, ev.Unexplained)))
}
