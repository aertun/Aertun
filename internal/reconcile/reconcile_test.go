// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)

func at(m float64) time.Time { return t0.Add(time.Duration(m * float64(time.Minute))) }

func input() Input {
	return Input{Since: t0, Until: t0.Add(time.Hour), Window: 2 * time.Minute}
}

// An agent whose spans account for every call the agent interface answered,
// however its host prefixed the tool, reconciles clean.
func TestAnAgentThatReportsWhatItDidReconciles(t *testing.T) {
	in := input()
	in.Calls = []Call{{at(5), "aertun_read"}, {at(20), "aertun_find"}, {at(30), "aertun_read"}}
	in.Spans = []Span{{at(4.9), "mcp__aertun__aertun_read"}, {at(19.5), "aertun.aertun_find"},
		{at(30.2), "aertun_read"}, {at(40), "shell"}}
	r := Reconcile(in)
	if r.Calls != 3 || r.Matched != 3 || len(r.Unreported) != 0 || len(r.Unreceived) != 0 ||
		r.Reported != 4 || r.ForInterface != 3 {
		t.Errorf("result %+v", r)
	}
}

// A call no span accounts for is unreported; a span for the agent interface
// no call matches is a call the agent says it made and the server never
// received. Each span answers for one call.
func TestWhatTheAccountsDisagreeOnIsNamed(t *testing.T) {
	in := input()
	in.Calls = []Call{{at(5), "aertun_read"}, {at(5.5), "aertun_read"}, {at(50), "aertun_write"}}
	in.Spans = []Span{{at(5.2), "aertun_read"}, {at(25), "mcp__aertun__aertun_write"},
		{at(50), "aertun_read"}}
	r := Reconcile(in)
	if r.Matched != 1 || len(r.Unreported) != 2 {
		t.Fatalf("result %+v", r)
	}
	if r.Unreported[0].At != at(5.5) || r.Unreported[1].Tool != "aertun_write" {
		t.Errorf("unreported %+v", r.Unreported)
	}
	if len(r.Unreceived) != 2 || r.Unreceived[0].Tool != "aertun_write" || r.Unreceived[1].At != at(50) {
		t.Errorf("unreceived %+v", r.Unreceived)
	}
}

// A tool name is matched exactly, or after a separator hosts use: a tool
// that only contains the name is somebody else's.
func TestAToolIsTheInterfacesOnlyByItsName(t *testing.T) {
	for name, want := range map[string]string{
		"aertun_read": "aertun_read", "mcp__aertun__aertun_read": "aertun_read",
		"srv/aertun_write": "aertun_write", "not_aertun_read": "", "aertun_readme": "",
		"shell": "", "": "",
	} {
		if got := interfaceTool(name); got != want {
			t.Errorf("%q is %q, want %q", name, got, want)
		}
	}
}

// A connection from the agent's own machine is explained by the agent
// acting near it; one while it reported nothing is unexplained. A machine it
// shares is skipped, never attributed, and a destination that is not an
// address and a port is not counted.
func TestConnectionsAreHeldToWhenTheAgentWasActing(t *testing.T) {
	in := input()
	in.Hosts, in.Shared = []string{"build01"}, []string{"shared02"}
	in.Spans = []Span{{at(10), "shell"}}
	in.Connects = []Connect{
		{at(11), "build01", "203.0.113.9", "443"},
		{at(40), "build01", "198.51.100.7", "22"},
		{at(40), "shared02", "198.51.100.7", "22"},
		{at(41), "build01", "/run/socket", ""},
		{at(42), "elsewhere", "198.51.100.8", "22"},
	}
	r := Reconcile(in)
	if r.Connects != 2 || r.SharedSkipped != 1 || len(r.Unexplained) != 1 ||
		r.Unexplained[0].Addr != "198.51.100.7" {
		t.Errorf("result %+v", r)
	}
}

// The period bounds what is counted; a span just outside it can still
// account for a call at its edge.
func TestThePeriodBoundsWhatIsCounted(t *testing.T) {
	in := input()
	in.Calls = []Call{{at(0.5), "aertun_read"}, {at(70), "aertun_read"}}
	in.Spans = []Span{{at(-1), "aertun_read"}, {at(-30), "aertun_read"}}
	r := Reconcile(in)
	if r.Calls != 1 || r.Matched != 1 || r.Reported != 0 || len(r.Unreceived) != 0 {
		t.Errorf("result %+v", r)
	}
}

// A call the server recorded under a name that is not one of its tools —
// a client may send any name, and is refused under it — is not a call to
// the interface, however it is spelt.
func TestOnlyTheServersOwnToolNamesAreCalls(t *testing.T) {
	in := input()
	in.Calls = []Call{{at(5), "x__aertun_read"}, {at(6), "aertun_read; drop"}, {at(7), "aertun_read"}}
	in.Spans = []Span{{at(7), "aertun_read"}}
	r := Reconcile(in)
	if r.Calls != 1 || r.Matched != 1 || len(r.Unreported) != 0 {
		t.Errorf("result %+v", r)
	}
}
