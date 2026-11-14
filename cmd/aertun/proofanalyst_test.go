// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aertun/aertun/internal/bench"
	"github.com/aertun/aertun/internal/decide"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
)

// An analyst that does what the log tells it is refuted on its hijacks,
// whatever its rates; the proof is signed, verifies against its key, is
// kept in the store as a triage proof, and carries none of the corpus's
// text. Fewer than three runs, no key, or no model is refused.
func TestProofAnalystRefutesAnAnalystTheLogCanSteer(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	analystSeam = func(string) (decide.Model, string) { return &bench.Stub{Obedient: true}, "" }
	t.Cleanup(func() { analystSeam = nil })
	key, pub := signingFiles(t)
	at := filepath.Join(t.TempDir(), "triage.json")

	if err := cmdProof(root, []string{"analyst", "--key", key, "--k", "2", "--out", at}); err == nil {
		t.Error("a proof over two runs per case was made")
	}
	if err := cmdProof(root, []string{"analyst", "--out", at}); err == nil {
		t.Error("an unsigned analyst proof was made")
	}
	if err := cmdProof(root, []string{"analyst", "--key", key, "--public-key", pub, "--out", at}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(at)
	if err != nil {
		t.Fatal(err)
	}
	var env proof.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	pk, err := pack.LoadPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	st, err := proof.Open(&env, pk)
	if err != nil {
		t.Fatalf("the proof does not verify: %v", err)
	}
	if st.Predicate.Verdict != proof.Refuted || st.Predicate.Triage.Hijacks.K == 0 {
		t.Fatalf("an obedient analyst was %s with %d hijacks", st.Predicate.Verdict, st.Predicate.Triage.Hijacks.K)
	}
	kept, err := proofstore.List(root)
	if err != nil || len(kept) != 1 || kept[0].Statement == nil || kept[0].Statement.PredicateType != proof.PredicateTriage {
		t.Fatalf("kept: %+v %v", kept, err)
	}
	if err := cmdProof(root, []string{"show", kept[0].ID}); err != nil {
		t.Errorf("proof show: %v", err)
	}

	analystSeam = func(string) (decide.Model, string) { return nil, "no model is configured" }
	if err := cmdProof(root, []string{"analyst", "--key", key, "--out", at}); err == nil {
		t.Error("an analyst proof was made with no model")
	}
}
