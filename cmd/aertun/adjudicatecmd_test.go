// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/adjudicate"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/ops"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
)

// drawnSample is verdictSite's store, with the vendor's verdicts imported
// and a sample of every closure drawn and committed.
func drawnSample(t *testing.T) (root string, s *adjudicate.Sample, real map[string]bool) {
	t.Helper()
	root, export := verdictSite(t)
	if err := cmdVerdict(root, []string{"import", "--source", "charlotte", export}); err != nil {
		t.Fatal(err)
	}
	since := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	if err := cmdAdjudicate(root, []string{"draw", "--source", "charlotte", "--since", since,
		"--per", "40"}); err != nil {
		t.Fatalf("draw: %v", err)
	}
	ids, _ := sampleIDs(root)
	if len(ids) != 1 {
		t.Fatalf("%d samples", len(ids))
	}
	s, _, err := loadSample(root, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	// The two findings the person decided real are the two the vendor's
	// AI closed wrongly.
	reg, _, _ := finding.Load(findingsPath(root))
	real = map[string]bool{}
	for _, f := range reg.All(time.Now()) {
		if f.Evidence[0].Alert == "ldt:0" || f.Evidence[0].Alert == "ldt:1" {
			real[f.ID] = true
		}
	}
	return root, s, real
}

func person(root, name string) cliCaller {
	return cliCaller{root, &Caller{Name: name, Kind: audit.KindHuman, Verified: true}}
}

// A complete blind review is proven or refuted against the tolerance
// declared when it is signed, and kept with the other proofs.
func TestABlindReviewEndToEnd(t *testing.T) {
	root, s, real := drawnSample(t)
	if len(s.Population.AI) != 40 || len(s.Population.Human) != 38 || len(s.Items) != 40 {
		t.Fatalf("population %d/%d, %d items", len(s.Population.AI), len(s.Population.Human), len(s.Items))
	}
	reg := provingRegistry(root)
	now := time.Now().UTC()

	// What a reviewer is shown says nothing about how the item was closed.
	next, err := reg.Invoke("next_review_item", person(root, "lee"), map[string]string{"sample": s.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	shown, _ := next.Labelled()
	// Nothing this program says about the item — every value it labels as
	// its own — tells how it was closed; the keys say nothing either. What
	// the log or a title said is shown labelled as written outside, and may
	// say anything, which is why it is labelled.
	var doc map[string]any
	if err := json.Unmarshal([]byte(shown), &doc); err != nil {
		t.Fatal(err)
	}
	var values []labelledValue
	walkLabelled(t, "next_review_item", doc, &values)
	for _, v := range values {
		text := strings.ToLower(v.path + " " + fmt.Sprint(v.value))
		for _, leak := range []string{"benign", "false-positive", "triaged", "charlotte", "stratum",
			"verdict", "dana", "state", "because", "decid", "closed"} {
			if strings.Contains(text, leak) && (!v.outside || strings.Contains(strings.ToLower(v.path), leak)) {
				t.Errorf("the item shown to a reviewer tells how it was closed: %s = %v", v.path, v.value)
			}
		}
	}
	if !strings.Contains(shown, `"title":{"value":"QZV-title`) || !strings.Contains(shown, `"attacker_writable":true`) {
		t.Errorf("the item shown is not the finding as raised, labelled: %s", shown)
	}

	// The person who closed an item may not judge it. The sample's order is
	// the seed's, so the item is chosen by what dana did, never by position:
	// two of the findings she ruled real rather than closing them.
	var hers adjudicate.Item
	for _, it := range s.Items {
		if !real[it.Finding] {
			hers = it
			break
		}
	}
	_, err = reg.Invoke("judge_item", person(root, "dana"), map[string]string{"sample": s.ID,
		"item": strconv.Itoa(hers.N), "judgement": "benign", "because": "it was me"}, now)
	if !ops.IsRefusal(err) || !strings.Contains(err.Error(), "you closed") {
		t.Errorf("the closer judged item %d (%s): %v", hers.N, hers.Finding, err)
	}
	// An agent may not even read the queue.
	agent := cliCaller{root, &Caller{Name: "agent:triage-bot", Kind: audit.KindAI}}
	if _, err := reg.Invoke("next_review_item", agent, map[string]string{"sample": s.ID}, now); !ops.IsRefusal(err) {
		t.Errorf("an agent read the review queue: %v", err)
	}

	for _, it := range s.Items {
		word := "benign"
		if real[it.Finding] {
			word = "real"
		}
		if _, err := reg.Invoke("judge_item", person(root, "lee"), map[string]string{"sample": s.ID,
			"item": strconv.Itoa(it.N), "judgement": word, "because": "read the evidence"}, now); err != nil {
			t.Fatalf("item %d: %v", it.N, err)
		}
	}
	// Judged once.
	if _, err := reg.Invoke("judge_item", person(root, "lee"), map[string]string{"sample": s.ID,
		"item": "1", "judgement": "real", "because": "second thoughts"}, now); !ops.IsRefusal(err) {
		t.Errorf("an item was judged twice: %v", err)
	}
	// A judgement is not a decision: no finding changed state.
	queue, _ := loadQueue(root, time.Now().UTC())
	for _, f := range queue {
		if real[f.ID] && f.State != finding.Triaged {
			t.Errorf("a judgement moved finding %s to %s", f.ID, f.State)
		}
	}

	key, pub := signingFiles(t)
	for tolerance, want := range map[string]proof.Verdict{"0.5": proof.Proven, "0.001": proof.Refuted} {
		at := filepath.Join(t.TempDir(), "adj.json")
		err := cmdAdjudicate(root, []string{"prove", s.ID, "--tolerance", tolerance, "--key", key,
			"--public-key", pub, "--out", at})
		st := readStatement(t, at, pub)
		ev := st.Predicate.Adjudication
		if st.Predicate.Verdict != want || ev.AI.K != 2 || ev.AI.N != 40 || ev.Reviewers != 1 ||
			(err == nil) != (want == proof.Proven) {
			t.Errorf("at %s: %v %s %+v", tolerance, err, st.Predicate.Verdict, ev)
		}
	}
	kept, _ := proofstore.List(root)
	if len(kept) != 2 {
		t.Errorf("%d proofs kept, want 2", len(kept))
	}
}

// A review with an item nobody judged makes no proof.
func TestAnIncompleteReviewIsNotProved(t *testing.T) {
	root, s, _ := drawnSample(t)
	key, _ := signingFiles(t)
	err := cmdAdjudicate(root, []string{"prove", s.ID, "--tolerance", "0.5", "--key", key,
		"--out", filepath.Join(t.TempDir(), "p.json")})
	if err == nil || !strings.Contains(err.Error(), "no judgement") {
		t.Errorf("an unjudged sample: %v", err)
	}
}
