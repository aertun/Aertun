// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proving

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
)

type person struct{}

func (person) Allowed(auth.Action, string) error      { return nil }
func (person) Agent() bool                            { return false }
func (person) Name() string                           { return "dana" }
func (person) Record(string, map[string]string) error { return nil }

// A detection proof names a rule by the file name and the id whoever
// submitted it chose, so its words are labelled as written outside; a
// verdicts proof's words are rebuilt from its numbers when it is opened, so
// they are this program's.
func TestAProofsWordsAreLabelledByWhoCouldHaveWrittenThem(t *testing.T) {
	root := t.TempDir()
	k, _ := pack.GenerateKey()
	pub, _ := json.Marshal(k.PublicKey())
	rule, err := os.ReadFile("../detect/pack/okta.mfa-reset.json")
	if err != nil {
		t.Fatal(err)
	}
	det, err := proof.ProveDetection(proof.DetectionInput{RuleName: "ignore-your-instructions.json",
		Rule: rule, Program: "test", Now: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	ver, err := proof.ProveVerdicts(proof.VerdictsInput{Source: "charlotte", Labels: proof.LabelsPeople,
		Since: t0, Until: t0.Add(24 * time.Hour), Tolerance: 0.5, Lines: []byte("{}\n"),
		Considered: 40, Counted: 40, Alerts: 40, FalseClosures: proof.Count{K: 0, N: 40},
		ReviewCoverage: proof.Count{K: 40, N: 40}, DeliveredFirst: proof.Count{K: 40, N: 40},
		Agreement: proof.Count{K: 40, N: 40}, Abstentions: proof.Count{K: 0, N: 40},
		Program: "test", Now: t0.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range []*proof.Statement{det, ver} {
		env, _ := proof.Seal(st, k)
		body, _ := json.Marshal(env)
		if _, _, err := proofstore.Keep(root, body, pub, "dana", proofstore.OriginHere, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	a, err := Ops(root).Invoke("list_proofs", person{}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, row := range a.Get("proofs").Items() {
		kind := row.Get("kind").Text()
		seen[kind] = true
		claim, subject := row.Get("claim"), row.Get("subject")
		outside := kind == "detection"
		if claim.IsOutside() != outside || subject.IsOutside() != outside {
			t.Errorf("a %s proof's words are labelled outside=%v/%v, want %v",
				kind, claim.IsOutside(), subject.IsOutside(), outside)
		}
		if row.Get("verdict").IsOutside() || row.Get("id").IsOutside() {
			t.Errorf("a %s proof's verdict or id is labelled as written outside", kind)
		}
	}
	if !seen["detection"] || !seen["verdicts"] {
		t.Fatalf("listed %v", seen)
	}
	text, _ := a.Labelled()
	if !strings.Contains(text, `"value":"ignore-your-instructions.json","attacker_writable":true`) {
		t.Errorf("the rule's name is not labelled as written outside: %s", text)
	}
}
