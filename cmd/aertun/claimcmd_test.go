// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
	"github.com/aertun/aertun/internal/telemetry"
)

// claimSite is a store whose 40 findings were raised from the vendor's
// alerts ldt:0 … ldt:39 and not yet decided.
func claimSite(t *testing.T) (string, []string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	raised := time.Now().UTC().Add(-2 * time.Hour)
	reg := finding.NewRegister()
	var ids []string
	for i := range 40 {
		f, _ := reg.Record(finding.Finding{Kind: finding.FromDetection, Source: "crowdstrike-rule",
			Severity: telemetry.SeverityHigh, State: finding.Open,
			Entity: telemetry.ID{Issuer: "crowdstrike", Value: fmt.Sprintf("host-%d", i)},
			Title:  "an alert", Evidence: []finding.Evidence{{At: raised, What: "x",
				Source: "crowdstrike/alerts", Alert: fmt.Sprintf("ldt:%d", i), Tainted: true}}}, raised)
		ids = append(ids, f.ID)
	}
	if err := finding.Save(findingsPath(root), reg, nil); err != nil {
		t.Fatal(err)
	}
	return root, ids
}

// verdictsThenDecisions brings in the vendor's 40 verdicts, given now, and
// then a verified person's decisions on them: they agree on all but two.
func verdictsThenDecisions(t *testing.T, root string, ids []string) {
	t.Helper()
	var csv strings.Builder
	csv.WriteString("alert,verdict,at\n")
	given := time.Now().UTC().Format(time.RFC3339Nano)
	for i := range 40 {
		fmt.Fprintf(&csv, "ldt:%d,benign,%s\n", i, given)
	}
	export := filepath.Join(t.TempDir(), "charlotte.csv")
	if err := os.WriteFile(export, []byte(csv.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdVerdict(root, []string{"import", "--source", "charlotte", export}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond) // decisions follow the verdicts on the log's clock
	for i, id := range ids {
		to := finding.Benign
		if i < 2 {
			to = finding.Triaged
		}
		rec := finding.Decision{Finding: id, At: time.Now().UTC(), By: "dana", Kind: audit.KindHuman, To: to}.Record()
		rec.Verified = true
		if err := recordE(root, rec); err != nil {
			t.Fatal(err)
		}
	}
}

func testClaim(t *testing.T, root, name string, at time.Time) (*proof.Statement, error) {
	t.Helper()
	claimNow = func() time.Time { return at }
	t.Cleanup(func() { claimNow = time.Now })
	key, pub := signingFiles(t)
	out := filepath.Join(t.TempDir(), name+".json")
	err := cmdClaim(root, []string{"test", name, "--key", key, "--public-key", pub, "--out", out})
	return readStatement(t, out, pub), err
}

// A card counts only what arrived after it was registered, decides nothing
// while its window is open, and once it has closed is proven or refuted by
// its own bound; it cannot be registered twice.
func TestAClaimCardEndToEnd(t *testing.T) {
	root, ids := claimSite(t)
	for name, threshold := range map[string]string{"modest": "0.5", "boastful": "0.999"} {
		if err := cmdClaim(root, []string{"register", "charlotte-" + name, "--source", "charlotte",
			"--metric", "agreement", "--direction", "at-least", "--threshold", threshold,
			"--window-days", "30"}); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}
	if err := cmdClaim(root, []string{"register", "charlotte-modest", "--source", "charlotte",
		"--metric", "agreement", "--direction", "at-least", "--threshold", "0.1"}); err == nil {
		t.Error("a card was registered twice under one name")
	}
	verdictsThenDecisions(t, root, ids)

	open, err := testClaim(t, root, "charlotte-modest", time.Now().UTC().Add(24*time.Hour))
	if err == nil || open.Predicate.Verdict != proof.Inconclusive || open.Predicate.ClaimTest.N != 40 {
		t.Errorf("with the window open: %v %s %+v", err, open.Predicate.Verdict, open.Predicate.ClaimTest)
	}
	if kept, _ := proofstore.List(root); len(kept) != 0 {
		t.Errorf("a test with the window open was kept: %d", len(kept))
	}
	later := time.Now().UTC().Add(31 * 24 * time.Hour)
	if st, err := testClaim(t, root, "charlotte-modest", later); err != nil || st.Predicate.Verdict != proof.Proven {
		t.Errorf("38 of 40 against at least 0.5: %v %s", err, st.Predicate.Verdict)
	}
	if st, _ := testClaim(t, root, "charlotte-boastful", later); st.Predicate.Verdict != proof.Refuted {
		t.Errorf("38 of 40 against at least 0.999: %s", st.Predicate.Verdict)
	}
	if kept, _ := proofstore.List(root); len(kept) != 2 {
		t.Errorf("%d proofs kept, want 2", len(kept))
	}
}

// What arrived before the card was registered is not counted: a card made
// after the numbers were seen tests nothing.
func TestACardCountsNothingFromBeforeItWasRegistered(t *testing.T) {
	root, ids := claimSite(t)
	verdictsThenDecisions(t, root, ids)
	if err := cmdClaim(root, []string{"register", "after-the-fact", "--source", "charlotte",
		"--metric", "agreement", "--direction", "at-least", "--threshold", "0.5"}); err != nil {
		t.Fatal(err)
	}
	st, _ := testClaim(t, root, "after-the-fact", time.Now().UTC().Add(31*24*time.Hour))
	if st.Predicate.ClaimTest.N != 0 || st.Predicate.Verdict != proof.Inconclusive {
		t.Errorf("a card counted what came before it: %+v", st.Predicate.ClaimTest)
	}
}

// A card edited on disk after registering matches no registration, and is
// refused rather than tested.
func TestAnEditedCardIsNotTested(t *testing.T) {
	root, _ := claimSite(t)
	if err := cmdClaim(root, []string{"register", "edited", "--source", "charlotte",
		"--metric", "agreement", "--direction", "at-least", "--threshold", "0.99"}); err != nil {
		t.Fatal(err)
	}
	p := claimPath(root, "edited")
	body, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte(strings.Replace(string(body), "0.99", "0.5", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	key, _ := signingFiles(t)
	if err := cmdClaim(root, []string{"test", "edited", "--key", key}); err == nil ||
		!strings.Contains(err.Error(), "registered 0 times") {
		t.Errorf("an edited card: %v", err)
	}
}

// A card about blind review is tested on the one sample drawn for it after
// it was registered.
func TestABlindReviewCardIsTestedOnItsOwnSample(t *testing.T) {
	root, ids := claimSite(t)
	if err := cmdClaim(root, []string{"register", "charlotte-blind", "--source", "charlotte",
		"--metric", "adjudicated-false-closures", "--direction", "at-most", "--threshold", "0.5",
		"--window-days", "30"}); err != nil {
		t.Fatal(err)
	}
	verdictsThenDecisions(t, root, ids)
	since := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if err := cmdAdjudicate(root, []string{"draw", "--source", "charlotte", "--since", since,
		"--per", "40", "--claim", "charlotte-blind"}); err != nil {
		t.Fatalf("draw: %v", err)
	}
	sids, _ := sampleIDs(root)
	s, _, _ := loadSample(root, sids[0])
	reg := provingRegistry(root)
	for _, it := range s.Items {
		word := "benign"
		if it.Finding == ids[0] || it.Finding == ids[1] {
			word = "real"
		}
		if _, err := reg.Invoke("judge_item", person(root, "lee"), map[string]string{"sample": s.ID,
			"item": fmt.Sprint(it.N), "judgement": word, "because": "read it"}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	st, err := testClaim(t, root, "charlotte-blind", time.Now().UTC().Add(31*24*time.Hour))
	ev := st.Predicate.ClaimTest
	if err != nil || st.Predicate.Verdict != proof.Proven || ev.K != 2 || ev.N != 40 {
		t.Errorf("2 of 40 judged real against at most 0.5: %v %s %+v", err, st.Predicate.Verdict, ev)
	}
}
