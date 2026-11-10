// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package adjudicate

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/stats"
	"github.com/aertun/aertun/internal/verdict"
)

var t0 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func seedOf(b byte) string { return hex.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

func ids(prefix string, n int) []string {
	var out []string
	for i := range n {
		out = append(out, fmt.Sprintf("%s%03d", prefix, i))
	}
	sort.Strings(out)
	return out
}

// The selection is the per lowest HMAC-SHA256 values under the seed, which
// anybody can recompute with nothing but the seed and the population; this
// recomputes it the long way.
func TestTheSelectionIsWhatTheSeedDecides(t *testing.T) {
	pop := Population{AI: ids("a", 40), Human: ids("h", 25)}
	seed := seedOf(7)
	items, err := Select(pop, seed, 10)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString(seed)
	lowest := func(label string, from []string) map[string]bool {
		type ranked struct{ id, mac string }
		var rs []ranked
		for _, id := range from {
			m := hmac.New(sha256.New, key)
			m.Write([]byte(label + "\x00" + id))
			rs = append(rs, ranked{id, hex.EncodeToString(m.Sum(nil))})
		}
		sort.Slice(rs, func(i, j int) bool { return rs[i].mac < rs[j].mac })
		out := map[string]bool{}
		for _, r := range rs[:10] {
			out[r.id] = true
		}
		return out
	}
	wantAI, wantHuman := lowest("ai", pop.AI), lowest("human", pop.Human)
	gotAI, gotHuman := 0, 0
	for i, it := range items {
		if it.N != i+1 || it.AI != wantAI[it.Finding] || it.Human != wantHuman[it.Finding] {
			t.Errorf("item %+v is not what the seed selects", it)
		}
		if it.AI {
			gotAI++
		}
		if it.Human {
			gotHuman++
		}
	}
	if gotAI != 10 || gotHuman != 10 || len(items) != 20 {
		t.Errorf("%d items, %d ai, %d human", len(items), gotAI, gotHuman)
	}
	again, _ := Select(pop, seed, 10)
	other, _ := Select(pop, seedOf(8), 10)
	if fmt.Sprint(again) != fmt.Sprint(items) || fmt.Sprint(other) == fmt.Sprint(items) {
		t.Error("the same seed drew differently, or another seed drew the same")
	}
}

// A finding both strata selected is reviewed once and counts in both; a
// stratum smaller than the size asked for gives all it has.
func TestOverlapAndShortStrata(t *testing.T) {
	pop := Population{AI: []string{"f1", "f2"}, Human: []string{"f2", "f3"}}
	items, err := Select(pop, seedOf(1), 30)
	if err != nil {
		t.Fatal(err)
	}
	s := &Sample{Items: items}
	if ai, human := s.Counts(); len(items) != 3 || ai != 2 || human != 2 {
		t.Errorf("items %+v", items)
	}
	if _, err := Draw("charlotte", t0, t0, "", Population{}, seedOf(1), 30); err == nil {
		t.Error("an empty population drew a sample")
	}
}

func TestTheSeedComesFromTheReaderItIsGiven(t *testing.T) {
	s, err := NewSeed(bytes.NewReader(bytes.Repeat([]byte{9}, 32)))
	if err != nil || s != seedOf(9) {
		t.Errorf("seed %q, %v", s, err)
	}
	if _, err := NewSeed(bytes.NewReader([]byte{1, 2})); err == nil {
		t.Error("a short read made a seed")
	}
}

func TestClosuresReadsBothStrata(t *testing.T) {
	ev := func(ref string) []finding.Evidence { return []finding.Evidence{{Alert: ref}} }
	findings := []finding.Finding{
		{ID: "f1", Kind: finding.FromDetection, Evidence: ev("k1")},
		{ID: "f2", Kind: finding.FromDetection, Evidence: ev("k2")},
		{ID: "f3", Kind: finding.FromDetection, Evidence: ev("k3")},
		{ID: "v1", Kind: finding.FromVulnerability},
	}
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	vs := []verdict.Verdict{
		{Source: "charlotte", Alert: "k1", Says: verdict.Real, At: at(1), Imported: at(1)},
		{Source: "charlotte", Alert: "k1", Says: verdict.Benign, At: at(2), Imported: at(2)},
		{Source: "charlotte", Alert: "k2", Says: verdict.Benign, At: at(1), Imported: at(1)},
		{Source: "charlotte", Alert: "k2", Says: verdict.Escalate, At: at(3), Imported: at(3)},
		{Source: "charlotte", Alert: "nowhere", Says: verdict.FalsePositive, At: at(1), Imported: at(1)},
		{Source: "other", Alert: "k3", Says: verdict.Benign, At: at(1), Imported: at(1)},
	}
	people := []finding.Decision{
		{Finding: "f3", To: finding.FalsePositive, At: at(5)},
		{Finding: "f2", To: finding.Benign, At: at(5)},
		{Finding: "f2", To: finding.Triaged, At: at(6)},
		{Finding: "v1", To: finding.FalsePositive, At: at(5)},
	}
	pop := Closures(PopulationInput{Source: "charlotte", Since: t0, Until: at(100),
		Verdicts: vs, Findings: findings, People: people})
	if strings.Join(pop.AI, ",") != "f1" || strings.Join(pop.Human, ",") != "f3" || pop.Unlinked != 1 {
		t.Errorf("population %+v", pop)
	}
}

// review is a log with a committed sample in it, and a way to judge.
type review struct {
	t   *testing.T
	log *audit.Log
	at  string
	s   *Sample
}

func newReview(t *testing.T) *review {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.New(audit.Options{Path: path, Key: []byte("0123456789abcdef0123456789abcdef"),
		Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	pop := Population{AI: []string{"f1", "f2", "f3"}, Human: []string{"f3", "f4"}}
	s, err := Draw("charlotte", t0, t0.Add(time.Hour), "", pop, seedOf(3), 10)
	if err != nil {
		t.Fatal(err)
	}
	r := &review{t: t, log: l, at: path, s: s}
	// Dana closed f4 before any of this.
	r.append("finding.false-positive", "dana", true, map[string]string{"finding": "f4", "to": "false-positive", "because": "x"})
	r.append(DrawnAction, "lee", true, s.CommitDetail())
	return r
}

func (r *review) append(action, who string, verified bool, detail map[string]string) {
	r.t.Helper()
	if _, err := r.log.Append(audit.Record{Action: action, Resource: "/r", Outcome: audit.Success,
		Principal: who, Kind: audit.KindHuman, Verified: verified, Detail: detail}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *review) judge(n int, who string, says verdict.Word) {
	r.t.Helper()
	it, _ := r.s.Item(n)
	j := Judgement{Sample: r.s.ID, N: n, Finding: it.Finding, Says: says, Because: "read the evidence"}
	if err := j.Validate(); err != nil {
		r.t.Fatal(err)
	}
	r.append(JudgedAction, who, true, j.Detail())
}

func (r *review) item(finding string) int {
	for _, it := range r.s.Items {
		if it.Finding == finding {
			return it.N
		}
	}
	r.t.Fatalf("%s is not in the sample", finding)
	return 0
}

func (r *review) verify() (*Result, error) {
	events, err := audit.Read(r.at)
	if err != nil {
		r.t.Fatal(err)
	}
	return Verify(r.s, events)
}

func TestACompleteReviewIsCounted(t *testing.T) {
	r := newReview(t)
	r.judge(r.item("f1"), "sam", verdict.Real)
	r.judge(r.item("f2"), "sam", verdict.Benign)
	r.judge(r.item("f3"), "kit", verdict.Real)
	r.judge(r.item("f4"), "sam", verdict.FalsePositive)
	res, err := r.verify()
	if err != nil {
		t.Fatal(err)
	}
	if res.AI != (verdict.Count{K: 2, N: 3}) || res.Human != (verdict.Count{K: 1, N: 2}) ||
		res.Judged != 4 || res.Reviewers != 2 || res.EarlierDraws != 0 {
		t.Errorf("result %+v", res)
	}
}

// The person who closed a finding does not review it.
func TestTheOriginalCloserIsNotAReviewer(t *testing.T) {
	r := newReview(t)
	r.judge(r.item("f1"), "sam", verdict.Real)
	r.judge(r.item("f2"), "sam", verdict.Benign)
	r.judge(r.item("f3"), "sam", verdict.Benign)
	r.judge(r.item("f4"), "dana", verdict.FalsePositive)
	if _, err := r.verify(); err == nil || !strings.Contains(err.Error(), "closed it in the first place") {
		t.Errorf("the closer's own review was counted: %v", err)
	}
}

func TestAJudgedSetThatIsNotTheSampleMakesNoResult(t *testing.T) {
	cases := map[string]func(r *review){
		"an item never judged": func(r *review) {
			r.judge(r.item("f1"), "sam", verdict.Real)
			r.judge(r.item("f2"), "sam", verdict.Real)
			r.judge(r.item("f3"), "sam", verdict.Real)
		},
		"an item judged twice": func(r *review) {
			for _, f := range []string{"f1", "f2", "f3", "f4", "f1"} {
				r.judge(r.item(f), "sam", verdict.Benign)
			}
		},
		"an item the sample does not have": func(r *review) {
			for _, f := range []string{"f1", "f2", "f3", "f4"} {
				r.judge(r.item(f), "sam", verdict.Benign)
			}
			r.append(JudgedAction, "sam", true, map[string]string{"sample": r.s.ID, "item": "1",
				"finding": "f9", "judgement": "benign", "because": "x"})
		},
		"a sample file edited after the commitment": func(r *review) {
			for _, f := range []string{"f1", "f2", "f3", "f4"} {
				r.judge(r.item(f), "sam", verdict.Benign)
			}
			r.s.Items = r.s.Items[:len(r.s.Items)-1]
		},
		"a judgement by an unproved identity": func(r *review) {
			for _, f := range []string{"f1", "f2", "f3"} {
				r.judge(r.item(f), "sam", verdict.Benign)
			}
			it, _ := r.s.Item(r.item("f4"))
			r.append(JudgedAction, "sam", false, Judgement{Sample: r.s.ID, N: it.N,
				Finding: it.Finding, Says: verdict.Benign, Because: "x"}.Detail())
		},
		"a second commitment": func(r *review) {
			for _, f := range []string{"f1", "f2", "f3", "f4"} {
				r.judge(r.item(f), "sam", verdict.Benign)
			}
			r.append(DrawnAction, "lee", true, r.s.CommitDetail())
		},
	}
	for name, do := range cases {
		r := newReview(t)
		do(r)
		if res, err := r.verify(); err == nil {
			t.Errorf("%s: counted %+v", name, res)
		}
	}
}

func TestAJudgementBeforeTheCommitmentIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := audit.New(audit.Options{Path: path, Source: "test"})
	s, _ := Draw("charlotte", t0, t0, "", Population{AI: []string{"f1"}}, seedOf(5), 5)
	rec := func(action string, d map[string]string) {
		if _, err := l.Append(audit.Record{Action: action, Resource: "/r", Outcome: audit.Success,
			Principal: "sam", Kind: audit.KindHuman, Verified: true, Detail: d}); err != nil {
			t.Fatal(err)
		}
	}
	rec(JudgedAction, Judgement{Sample: s.ID, N: 1, Finding: "f1", Says: verdict.Real, Because: "x"}.Detail())
	rec(DrawnAction, s.CommitDetail())
	events, _ := audit.Read(path)
	if _, err := Verify(s, events); err == nil || !strings.Contains(err.Error(), "before the sample was committed") {
		t.Errorf("a judgement made before the draw was counted: %v", err)
	}
}

func TestAJudgementNeedsAWordAndAReason(t *testing.T) {
	for _, j := range []Judgement{
		{Sample: "0123456789abcdef", N: 1, Says: verdict.Escalate, Because: "x"},
		{Sample: "0123456789abcdef", N: 1, Says: verdict.Real},
		{Sample: "0123456789abcdef", N: 1, Says: verdict.Real, Because: "two\nlines"},
		{Sample: "nope", N: 1, Says: verdict.Real, Because: "x"},
	} {
		if err := j.Validate(); err == nil {
			t.Errorf("%+v was accepted", j)
		}
	}
}

// With no failures the size is the closed form, and with failures it is the
// smallest n whose exact bound clears the rate.
func TestTheSampleSize(t *testing.T) {
	for _, c := range []struct{ rate, conf float64 }{{0.01, 0.95}, {0.05, 0.95}, {0.02, 0.99}, {0.1, 0.9}} {
		n, err := Size(c.rate, c.conf, 0)
		closed := int(math.Ceil(math.Log(1-c.conf) / math.Log(1-c.rate)))
		if err != nil || n != closed {
			t.Errorf("Size(%v, %v, 0) = %d, %v; the closed form gives %d", c.rate, c.conf, n, err, closed)
		}
	}
	if n, _ := Size(0.01, 0.95, 0); n != 299 {
		t.Errorf("1%% at 95%% needs %d, not 299", n)
	}
	n, err := Size(0.05, 0.95, 2)
	if err != nil || stats.ClopperPearsonUpper(2, n, 0.95) > 0.05 ||
		stats.ClopperPearsonUpper(2, n-1, 0.95) <= 0.05 {
		t.Errorf("Size(0.05, 0.95, 2) = %d, %v", n, err)
	}
	for _, bad := range [][2]float64{{0, 0.95}, {0.01, 1}, {1.5, 0.9}} {
		if _, err := Size(bad[0], bad[1], 0); err == nil {
			t.Errorf("Size(%v, %v) was answered", bad[0], bad[1])
		}
	}
}
