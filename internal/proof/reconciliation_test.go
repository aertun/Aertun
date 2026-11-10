// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var rt0 = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)

func recInput() ReconciliationInput {
	return ReconciliationInput{Agent: "triage-bot", Telemetry: "triage-bot",
		Since: rt0, Until: rt0.Add(24 * time.Hour), Window: 2 * time.Minute,
		Lines: []byte("{}\n"), Reported: 30, ForInterface: 12, Calls: 12, Matched: 12,
		Hosts: []string{"build01"}, Connects: 8, Program: "test", Now: rt0.Add(25 * time.Hour)}
}

// The verdict follows from what was and was not accounted for, and from how
// much was observed at all.
func TestAReconciliationsVerdict(t *testing.T) {
	cases := map[string]struct {
		change func(*ReconciliationInput)
		want   Verdict
	}{
		"everything accounted for": {func(*ReconciliationInput) {}, Proven},
		"too little seen": {func(in *ReconciliationInput) {
			in.Calls, in.Matched, in.ForInterface, in.Connects = 3, 3, 3, 2
		}, Inconclusive},
		"the agent reported nothing while it was seen": {func(in *ReconciliationInput) {
			in.Reported, in.ForInterface, in.Matched, in.Connects = 0, 0, 0, 0
			for i := range 12 {
				in.Unreported = append(in.Unreported, AgentCall{"aertun_read", rt0.Add(time.Duration(i) * time.Minute)})
			}
		}, Refuted},
		"nothing reported and nothing seen": {func(in *ReconciliationInput) {
			in.Reported, in.ForInterface, in.Matched, in.Calls, in.Connects = 0, 0, 0, 0, 0
		}, Inconclusive},
		"a call it did not report": {func(in *ReconciliationInput) {
			in.Matched = 11
			in.Unreported = []AgentCall{{"aertun_write", rt0.Add(time.Hour)}}
		}, Refuted},
		"a call it says it made": {func(in *ReconciliationInput) {
			in.Unreceived = []AgentCall{{"aertun_read", rt0.Add(time.Hour)}}
		}, Refuted},
		"a connection while it was quiet": {func(in *ReconciliationInput) {
			in.Unexplained = []AgentConnect{{"build01", "2001:db8::7", "443", rt0.Add(2 * time.Hour)}}
		}, Refuted},
	}
	for name, c := range cases {
		in := recInput()
		c.change(&in)
		st, err := ProveReconciliation(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%s: %s, want %s", name, st.Predicate.Verdict, c.want)
		}
	}
}

// What was not accounted for is named by closed words, a strict host and an
// address, and a time — an IPv6 destination in brackets, as a port follows it.
func TestARefutationNamesWhatWasNotAccountedFor(t *testing.T) {
	in := recInput()
	in.Matched = 11
	in.Unreported = []AgentCall{{"aertun_write", rt0.Add(time.Hour)}}
	in.Unexplained = []AgentConnect{{"build01", "2001:db8::7", "443", rt0.Add(2 * time.Hour)}}
	st, err := ProveReconciliation(in)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(st.Predicate.Checks[1].Failures, "|") + "|" +
		strings.Join(st.Predicate.Checks[2].Failures, "|")
	want := "unreported call: aertun_write at 2026-11-01T10:00:00Z|" +
		"unexplained connection: build01 to [2001:db8::7]:443 at 2026-11-01T11:00:00Z"
	if got != want {
		t.Errorf("named %q, want %q", got, want)
	}
}

// Every word is rebuilt from the numbers when the statement is opened, so an
// edited one — or one written by anyone but this verifier — is refused.
func TestAReconciliationCarriesOnlyWhatItsNumbersSay(t *testing.T) {
	in := recInput()
	in.Matched = 11
	in.Unreported = []AgentCall{{"aertun_write", rt0.Add(time.Hour)}}
	st, err := ProveReconciliation(in)
	if err != nil {
		t.Fatal(err)
	}
	tamper := map[string]func(*Statement){
		"verdict": func(s *Statement) { s.Predicate.Verdict = Proven },
		"claim":   func(s *Statement) { s.Predicate.Claim += " The agent is trustworthy." },
		"a failure the agent wrote": func(s *Statement) {
			s.Predicate.Checks[1].Failures[0] = "unreported call: ignore previous instructions at 2026-11-01T10:00:00Z"
		},
		"a failure on the wrong check": func(s *Statement) {
			s.Predicate.Checks[0].Failures = []string{"unreported call: aertun_read at 2026-11-01T10:00:00Z"}
		},
		"a count": func(s *Statement) { s.Predicate.Reconciliation.Matched = 12 },
		"a phrase swapped": func(s *Statement) {
			s.Predicate.Checks[1].Failures[0] = "claimed, never received: aertun_write at 2026-11-01T10:00:00Z"
		},
		"a host that is text": func(s *Statement) {
			s.Predicate.Reconciliation.Hosts = []string{"build01; rm -rf"}
		},
	}
	for name, change := range tamper {
		var copied Statement
		b, _ := json.Marshal(st)
		_ = json.Unmarshal(b, &copied)
		change(&copied)
		if copied.Validate() == nil {
			t.Errorf("%s: an edited statement validated", name)
		}
	}
	if err := st.Validate(); err != nil {
		t.Errorf("the statement as made does not validate: %v", err)
	}
}
