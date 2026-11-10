// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package adjudicate

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/verdict"
)

// The audit log holds both halves: the commitment, written before the first
// item is shown, and every judgement, written as it is made. Nothing about
// a review lives only in a file somebody could edit; the sample file says
// what was drawn, and the log says it was drawn first and judged after.

const (
	// DrawnAction commits a sample.
	DrawnAction = "adjudication.drawn"
	// JudgedAction records one judgement.
	JudgedAction = "adjudication.judged"
	// MaxBecause bounds a reviewer's reason.
	MaxBecause = 500
)

// CommitDetail is what the commitment records: enough for anybody with the
// sample file to check it is the one committed, and anybody with the
// population as well to recompute the selection.
func (s *Sample) CommitDetail() map[string]string {
	ai, human := s.Counts()
	d := map[string]string{
		"sample": s.ID, "source": s.Source, "seed": s.Seed,
		"sha256": s.SelectionDigest(), "population": s.PopulationDigest(),
		"items": strconv.Itoa(len(s.Items)), "ai": strconv.Itoa(ai),
		"human": strconv.Itoa(human),
		"since": s.Since.UTC().Format(time.RFC3339), "until": s.Until.UTC().Format(time.RFC3339),
	}
	if s.Claim != "" {
		d["claim"] = s.Claim
	}
	return d
}

// Judgement is what a reviewer decided about one item.
type Judgement struct {
	Sample  string
	N       int
	Finding string
	Says    verdict.Word
	// Because is the reviewer's reason. It is kept in the log beside the
	// judgement, for whoever reviews the reviewer, and never reaches a
	// proof.
	Because string
}

// Validate refuses a judgement that is not one of the three words, or has
// no reason.
func (j Judgement) Validate() error {
	if !ValidID(j.Sample) || j.N < 1 {
		return fmt.Errorf("a judgement names a sample and an item number")
	}
	if !j.Says.Disposition() {
		return fmt.Errorf("a judgement is real, false-positive or benign")
	}
	b := strings.TrimSpace(j.Because)
	if b == "" || len(b) > MaxBecause || strings.ContainsAny(b, "\r\n") {
		return fmt.Errorf("a judgement needs a reason, on one line of at most %d bytes: "+
			"whoever checks the review reads it", MaxBecause)
	}
	return nil
}

// Detail is what the judgement records.
func (j Judgement) Detail() map[string]string {
	return map[string]string{"sample": j.Sample, "item": strconv.Itoa(j.N),
		"finding": j.Finding, "judgement": string(j.Says),
		"because": strings.TrimSpace(j.Because)}
}

// Entry is an audit entry, by where it is in the chain.
type Entry struct {
	Seq  int64
	Hash string
	At   time.Time
}

// Commit is a commitment read back from the log.
type Commit struct {
	Entry
	Detail map[string]string
}

// Judged is a judgement read back from the log, with who made it as the log
// records them.
type Judged struct {
	Judgement
	Entry
	By       string
	Kind     audit.Kind
	Verified bool
}

func entryOf(e audit.Event) (Entry, bool) {
	at, err := time.Parse(time.RFC3339Nano, e.At)
	return Entry{Seq: e.Seq, Hash: e.Hash, At: at}, err == nil
}

// Commits are the commitments for sample id, in log order.
func Commits(events []audit.Event, id string) []Commit {
	var out []Commit
	for _, e := range events {
		if e.Action != DrawnAction || e.Detail["sample"] != id {
			continue
		}
		if en, ok := entryOf(e); ok {
			out = append(out, Commit{Entry: en, Detail: e.Detail})
		}
	}
	return out
}

// JudgedIn are the judgements recorded for sample id, in log order.
func JudgedIn(events []audit.Event, id string) []Judged {
	var out []Judged
	for _, e := range events {
		if e.Action != JudgedAction || e.Detail["sample"] != id {
			continue
		}
		en, ok := entryOf(e)
		n, err := strconv.Atoi(e.Detail["item"])
		if !ok || err != nil {
			n = 0 // an entry nobody could have written through here; Verify refuses it
		}
		out = append(out, Judged{Entry: en, By: e.Principal, Kind: e.Kind, Verified: e.Verified,
			Judgement: Judgement{Sample: id, N: n, Finding: e.Detail["finding"],
				Says: verdict.Word(e.Detail["judgement"])}})
	}
	return out
}

// Result is what a complete review found.
type Result struct {
	Commit Commit
	// AI and Human are the items each stratum gave and how many of them
	// were judged real: each side's false closures.
	AI, Human verdict.Count
	// RealAI and RealHuman are the item numbers judged real.
	RealAI, RealHuman []int
	Judged            int
	// Reviewers is how many different people judged.
	Reviewers int
	// EarlierDraws is how many samples of the same source were committed
	// before this one.
	EarlierDraws int
}

// Verify checks that the log commits this sample and that its judgements
// are exactly the sample, and counts them. It refuses, rather than counts
// around, anything that would make the rates mean something else: a
// broken chain, a sample that is not the one committed, an item judged
// twice or not at all, a judgement before the commitment, by somebody whose
// identity was not proved, by a model, or by somebody who closed the
// finding in the first place.
func Verify(s *Sample, events []audit.Event) (*Result, error) {
	if ok, problems := audit.Verify(events); !ok {
		return nil, fmt.Errorf("the audit log does not verify at entry %d (%s); nothing it "+
			"holds can be relied on", problems[0].Seq, problems[0].Reason)
	}
	if err := s.Check(); err != nil {
		return nil, err
	}
	commits := Commits(events, s.ID)
	if len(commits) != 1 {
		return nil, fmt.Errorf("sample %s is committed %d times in the audit log, and a "+
			"review counts only against the one commitment made before it began", s.ID, len(commits))
	}
	c := commits[0]
	if c.Detail["sha256"] != s.SelectionDigest() || c.Detail["population"] != s.PopulationDigest() ||
		c.Detail["seed"] != s.Seed || c.Detail["source"] != s.Source || c.Detail["claim"] != s.Claim {
		return nil, fmt.Errorf("sample %s is not the selection the audit log committed", s.ID)
	}
	r := &Result{Commit: c}
	for _, e := range events {
		if e.Action == DrawnAction && e.Seq < c.Seq && e.Detail["source"] == s.Source {
			r.EarlierDraws++
		}
	}
	decisions := finding.FromAudit(events)
	judged := map[int]Judged{}
	reviewers := map[string]bool{}
	for _, j := range JudgedIn(events, s.ID) {
		it, ok := s.Item(j.N)
		switch {
		case !ok || it.Finding != j.Finding:
			return nil, fmt.Errorf("the judged items are not the committed sample: an "+
				"entry at %d judges an item sample %s does not have", j.Seq, s.ID)
		case j.Seq <= c.Seq:
			return nil, fmt.Errorf("item %d was judged before the sample was committed", j.N)
		case !j.Verified || j.Kind != audit.KindHuman:
			return nil, fmt.Errorf("item %d was judged by somebody whose identity was "+
				"not proved, or by something that is not a person", j.N)
		case !j.Says.Disposition():
			return nil, fmt.Errorf("item %d was given a word that is not a judgement", j.N)
		case Closers(it.Finding, decisions)[j.By]:
			return nil, fmt.Errorf("item %d was judged by somebody who closed it in the "+
				"first place", j.N)
		}
		if _, twice := judged[j.N]; twice {
			return nil, fmt.Errorf("the judged items are not the committed sample: item %d "+
				"was judged more than once", j.N)
		}
		judged[j.N] = j
		reviewers[j.By] = true
	}
	var missing []string
	for _, it := range s.Items {
		j, ok := judged[it.N]
		if !ok {
			missing = append(missing, strconv.Itoa(it.N))
			continue
		}
		if it.AI {
			r.AI.N++
			if j.Says == verdict.Real {
				r.AI.K++
				r.RealAI = append(r.RealAI, it.N)
			}
		}
		if it.Human {
			r.Human.N++
			if j.Says == verdict.Real {
				r.Human.K++
				r.RealHuman = append(r.RealHuman, it.N)
			}
		}
	}
	if len(missing) > 0 {
		shown := missing[:min(len(missing), 10)]
		return nil, fmt.Errorf("the judged items are not the committed sample: %d of %d "+
			"items have no judgement (%s%s)", len(missing), len(s.Items),
			strings.Join(shown, ", "), map[bool]string{true: ", …"}[len(missing) > 10])
	}
	r.Judged, r.Reviewers = len(judged), len(reviewers)
	return r, nil
}

// Progress is which items have a judgement in the log, by item number, for
// showing the next one and the state of a review. Unlike Verify it checks
// nothing: an item somebody judged is not shown again either way.
func Progress(events []audit.Event, id string) map[int]bool {
	out := map[int]bool{}
	for _, j := range JudgedIn(events, id) {
		out[j.N] = true
	}
	return out
}

// Pending are the items with no judgement yet, in review order.
func (s *Sample) Pending(done map[int]bool) []Item {
	var out []Item
	for _, it := range s.Items {
		if !done[it.N] {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N < out[j].N })
	return out
}
