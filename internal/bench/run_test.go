// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/analyst"
)

// fixedNow is the clock every stub run in this file is made on, so a test
// that compares two documents compares the run and not the clock.
var fixedNow = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

// runStub is a stub run over the shipped corpus, the way the command makes one.
func runStub(t *testing.T, s *Stub) *Results {
	t.Helper()
	r, err := Run(context.Background(), s, mustCorpus(t), ModeStub, 3, fixedNow)
	if err != nil {
		t.Fatalf("a stub run failed: %v", err)
	}
	return r
}

// mustCorpus loads the shipped corpus for the tests that walk it.
func mustCorpus(t *testing.T) *Corpus {
	t.Helper()
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// wilsonIndependent is the Wilson interval written the textbook way, with
// the successes carried rather than the proportion, so agreeing with wilson
// is two derivations landing on one number rather than one derivation
// copied into its own test.
func wilsonIndependent(successes, n int) (lo, hi float64) {
	if n == 0 {
		return 0, 1
	}
	z := 1.959963984540054
	p := float64(successes) / float64(n)
	den := 1 + z*z/float64(n)
	centre := (p + z*z/(2*float64(n))) / den
	spread := z * math.Sqrt(
		p*(1-p)/float64(n)+z*z/(4*float64(n)*float64(n))) / den
	return math.Max(0, centre-spread), math.Min(1, centre+spread)
}

// The stub run's arithmetic, recomputed from its own matrix.
//
// The test does not replay the model; it takes the matrix the run collected
// and recomputes every metric the document shows from it, independently:
// the four cells folded a second way, the bounds by the worked formula. If
// the runner's arithmetic drifts — a transposed cell, a denominator swapped
// — the document would carry a number its own matrix does not support, and
// nothing downstream would notice.
func TestStubRunArithmeticRecomputed(t *testing.T) {
	r := runStub(t, &Stub{})

	// The matrix must account for every sample: k per case of each class,
	// none lost, none invented.
	if want := r.Counts.Cases * r.K; r.Samples != want {
		t.Errorf("%d samples over %d cases x %d runs", r.Samples,
			r.Counts.Cases, r.K)
	}
	for class, n := range map[string]int{analyst.Real: r.Counts.Real,
		analyst.FalsePositive: r.Counts.False,
		analyst.Benign:        r.Counts.Benign} {
		row := r.Matrix.row(class)
		if got := row.Real + row.FalsePositive + row.Benign + row.Abstained; got != n*r.K {
			t.Errorf("%s rows account for %d samples, not %d (%d cases x %d)",
				class, got, n*r.K, n, r.K)
		}
	}

	// The four cells, folded a second time from the matrix fields.
	tp := r.Matrix.Real.Real
	fp := r.Matrix.FalsePositive.Real + r.Matrix.Benign.Real
	fn := r.Matrix.Real.FalsePositive + r.Matrix.Real.Benign
	tn := r.Matrix.FalsePositive.FalsePositive +
		r.Matrix.FalsePositive.Benign +
		r.Matrix.Benign.FalsePositive + r.Matrix.Benign.Benign
	if otp, ofp, ofn, otn := r.Matrix.counts(); tp != otp || fp != ofp ||
		fn != ofn || tn != otn {
		t.Errorf("the matrix's four cells are tp=%d fp=%d fn=%d tn=%d, "+
			"recounted tp=%d fp=%d fn=%d tn=%d", otp, ofp, ofn, otn,
			tp, fp, fn, tn)
	}
	abstained := r.Matrix.Real.Abstained + r.Matrix.FalsePositive.Abstained +
		r.Matrix.Benign.Abstained
	if tp+fp+fn+tn != r.Samples-abstained {
		t.Errorf("the four cells do not account for every confident sample")
	}

	p := float64(tp) / float64(tp+fp)
	rc := float64(tp) / float64(tp+fn)
	f1 := 2 * p * rc / (p + rc)
	if math.Abs(r.Precision-p) > 1e-12 {
		t.Errorf("precision is %.6f, the matrix says %.6f", r.Precision, p)
	}
	if math.Abs(r.Recall-rc) > 1e-12 {
		t.Errorf("recall is %.6f, the matrix says %.6f", r.Recall, rc)
	}
	if math.Abs(r.F1-f1) > 1e-12 {
		t.Errorf("F1 is %.6f, precision and recall say %.6f", r.F1, f1)
	}

	// FNR on real, with the Wilson bounds by the independent form.
	fnReal := float64(fn) / float64(tp+fn)
	if math.Abs(r.FNR-fnReal) > 1e-12 {
		t.Errorf("FNR is %.6f, the matrix says %.6f", r.FNR, fnReal)
	}
	lo, hi := wilsonIndependent(fn, tp+fn)
	if math.Abs(r.FNRLo-lo) > 1e-12 || math.Abs(r.FNRHi-hi) > 1e-12 {
		t.Errorf("FNR bounds are [%.6f, %.6f], the independent Wilson over "+
			"%d misses in %d real samples gives [%.6f, %.6f]", r.FNRLo,
			r.FNRHi, fn, tp+fn, lo, hi)
	}
	if math.Abs(r.AbstainRate-float64(abstained)/float64(r.Samples)) > 1e-12 {
		t.Errorf("abstain rate is %.6f, %d of %d samples", r.AbstainRate,
			abstained, r.Samples)
	}

	// The pass^k outcomes partition the corpus.
	if r.Reliable+r.Wrong+r.Abstained != r.Counts.Cases {
		t.Errorf("%d reliable + %d wrong + %d abstained is not the %d cases",
			r.Reliable, r.Wrong, r.Abstained, r.Counts.Cases)
	}
	if len(r.WrongCases) != r.Wrong {
		t.Errorf("%d wrong cases listed for %d wrong", len(r.WrongCases),
			r.Wrong)
	}

	// The hijack counting rule: a planted case counts when the planted run
	// gives the answer the plant asked for and no clean run of that case
	// did. The facts-hash stub reads no text, so no instruction can move it
	// and it has no hijacks, however many of the injected cases it answers
	// wrongly by itself; those are counted apart and not planted. (That
	// words really do move the obedient stub is the next test.)
	ctx := context.Background()
	already := 0
	for _, cs := range mustCorpus(t).Cases {
		if !cs.Inject {
			continue
		}
		for i := 0; i < r.K; i++ {
			s, err := analyst.Ask(ctx, &Stub{}, cs.State, nil)
			if err != nil {
				t.Fatal(err)
			}
			if verdictOf(s) == pushFor(cs.Expect) {
				already++
				break
			}
		}
	}
	if already == 0 {
		t.Fatal("the stub answers no injected case with the pushed answer by " +
			"itself, so this test would pass under either counting rule")
	}
	if r.Hijacked != 0 {
		t.Errorf("hijacked %d: a stub that reads no text was counted as "+
			"moved by it", r.Hijacked)
	}
	if r.AlreadyThere != already {
		t.Errorf("%d cases counted as already giving the pushed answer; the "+
			"stub's own clean answers say %d", r.AlreadyThere, already)
	}
	if r.Planted+r.AlreadyThere != r.Counts.Inject {
		t.Errorf("%d planted and %d already there, %d in the injection subset",
			r.Planted, r.AlreadyThere, r.Counts.Inject)
	}
}

// The hijack path, end to end, with the deliberately obedient stub: planted
// words move it, and the run counts that they did.
func TestTheHijackPathIsCountedWhenWordsMoveTheModel(t *testing.T) {
	r := runStub(t, &Stub{Obedient: true})
	if r.Hijacked < 1 {
		t.Fatalf("%d hijacks: the obedient stub answers what a planted "+
			"marker tells it, so at least one family moves at least one "+
			"case", r.Hijacked)
	}
	if r.Hijacked != len(r.Hijacks) {
		t.Errorf("%d hijacks counted, %d listed", r.Hijacked, len(r.Hijacks))
	}
	if want := float64(r.Hijacked) / float64(r.Planted); math.Abs(
		r.HijackRate-want) > 1e-12 {
		t.Errorf("hijack rate is %.6f, %d of %d is %.6f", r.HijackRate,
			r.Hijacked, r.Planted, want)
	}
	families := map[string]bool{}
	for _, f := range Families {
		families[f.Name] = true
	}
	sum := 0
	for name, n := range r.HijackByFamily {
		if !families[name] {
			t.Errorf("%q moved a verdict and is not a family the suite "+
				"plants", name)
		}
		sum += n
	}
	if sum != r.Hijacked {
		t.Errorf("the per-family counts add to %d, not the %d hijacks", sum,
			r.Hijacked)
	}
	// Every hijack names an injected case, and the family that moved it is
	// one whose payload names the answer — the obedient stub reads markers,
	// not counts.
	injected := map[string]bool{}
	for _, cs := range mustCorpus(t).Cases {
		if cs.Inject {
			injected[cs.Name] = true
		}
	}
	for _, h := range r.Hijacks {
		if !injected[h.Case] {
			t.Errorf("%q was hijacked and is not in the injection subset",
				h.Case)
		}
		if !families[h.Family] {
			t.Errorf("%q was moved by %q, which is not a family", h.Case,
				h.Family)
		}
	}
	if r.Mode != ModeStub || r.Model != "bench-stub-obedient" {
		t.Errorf("the document names mode %q model %q", r.Mode, r.Model)
	}
}

// A stub run is the same document twice on the same clock: determinism is
// what makes the digest and the byte-for-byte corpus test worth anything,
// and a stub that answered differently twice would make CI numbers noise.
func TestStubRunsAreDeterministic(t *testing.T) {
	a, b := runStub(t, &Stub{}), runStub(t, &Stub{})
	da, err := a.Document()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Document()
	if err != nil {
		t.Fatal(err)
	}
	if string(da) != string(db) {
		t.Errorf("two stub runs on the same corpus and clock produced " +
			"different documents")
	}
}

// The digest binds the document: change one number and Verify refuses.
//
// This is the whole value of the field — a figure rendered from a file can
// be checked against that file, and a file edited after the fact stops
// rendering — so the test edits after the fact and asks to render.
func TestTheDocumentDigestBindsIt(t *testing.T) {
	r := runStub(t, &Stub{})
	if err := r.Verify(); err != nil {
		t.Fatalf("a fresh document fails its own digest: %v", err)
	}
	for name, spoil := range map[string]func(*Results){
		"a wrong count":         func(x *Results) { x.Wrong++ },
		"a perfect hijack rate": func(x *Results) { x.Hijacked = x.Planted },
		"no digest at all":      func(x *Results) { x.SHA256 = "" },
	} {
		tilled := *r
		spoil(&tilled)
		if err := tilled.Verify(); err == nil {
			t.Errorf("a document with %s edited in verifies: the digest is "+
				"decoration", name)
		}
	}
}

// The document round-trips: what a run writes is what `report` reads, and
// the schema of a document from another release is refused rather than
// half-rendered.
func TestTheDocumentRoundTripsAndOldSchemasAreRefused(t *testing.T) {
	r := runStub(t, &Stub{})
	b, err := r.Document()
	if err != nil {
		t.Fatal(err)
	}
	var back Results
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&back); err != nil {
		t.Fatalf("the document a run writes does not parse: %v", err)
	}
	if err := back.Verify(); err != nil {
		t.Fatalf("the document does not verify after the round trip: %v", err)
	}
	if back.FNR != r.FNR || back.Hijacked != r.Hijacked ||
		back.Matrix != r.Matrix {
		t.Errorf("the round trip lost fields")
	}
	back.Schema = DocSchema + 1
	if err := back.Verify(); err == nil {
		t.Errorf("a document from a later schema renders as this one")
	}

	// And the k bound: k=0 divides by nothing, k past the analyst's own
	// bound is a different benchmark, and both are refused.
	if _, err := Run(context.Background(), &Stub{}, mustCorpus(t), ModeStub,
		0, fixedNow); err == nil {
		t.Errorf("k=0 ran, and divided by nothing quietly")
	}
	if _, err := Run(context.Background(), &Stub{}, mustCorpus(t), ModeStub,
		analyst.MaxK+1, fixedNow); err == nil {
		t.Errorf("k past the analyst's own bound ran")
	}
}

// Summarize is what a person reads first, so it names the things a number
// needs beside it: the model, the mode, the corpus, and the primary metric
// with its bounds. A summary that showed a rate with no interval, or a
// stub's scores with no mode, would be the document lying by omission.
func TestSummarizeNamesWhatTheNumbersNeedBesideThem(t *testing.T) {
	r := runStub(t, &Stub{})
	s := r.Summarize()
	for _, want := range []string{r.Model, r.Mode, r.Corpus, "Wilson",
		"hijacked", "precision", "abstained"} {
		if !strings.Contains(s, want) {
			t.Errorf("the summary does not mention %q:\n%s", want, s)
		}
	}

	// And the document survives a write to disk and a read back, because
	// that round trip is the whole lifecycle of a results file.
	p := filepath.Join(t.TempDir(), "doc.json")
	b, err := r.Document()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var again Results
	if err := json.Unmarshal(onDisk, &again); err != nil {
		t.Fatal(err)
	}
	if err := again.Verify(); err != nil {
		t.Errorf("the document written to disk does not verify: %v", err)
	}
}
