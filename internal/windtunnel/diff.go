// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// The regression diff: two sealed scorecards in, the transitions between
// them out, and an exit code a CI job can gate on — the documents are
// self-contained, so no store and no history exist to consult (decision
// 10's payoff).
//
// # The grammar
//
// Per scenario, the outcome transition is read as one of three words:
//
//   - regression — anything → missed. The controls that caught it no
//     longer do, whatever they were doing before.
//   - fix — missed → anything. The other direction, named for what it is.
//   - drift — any other change of tier (caught-alert → caught-telemetry
//     and friends): reported, named, never gated on. A gate that failed on
//     every movement would be a gate nobody enables.
//
// The twin axis is its own transition: quiet → false-fire is a regression
// (the precision axis failed; every catch above it is noise until the twin
// is quiet again), false-fire → quiet is a fix. Scenarios that ran in only
// one document are new or retired, reported so a diff over a subset run
// cannot pretend it compared the whole corpus. The aggregate carries both
// sides' miss rates with their Wilson bounds, and the ambient drift is
// told apart from rule findings: if the base stream's own alerts moved,
// the estate moved, and no transition in that diff is a fact about the
// rules alone.
//
// # What refuses to diff at all
//
// Documents from different engines, different scoring modes or different
// corpora are refused: a scorecard's numbers are only comparable against
// the engine that produced them, and modes are never pooled — a reference
// card and a their-Sigma card measure different subjects and a transition
// between them would be a fact about the join, not about the controls.
//
// # Determinism
//
// Everything is sorted — scenarios by id, everything else in declaration
// order — and nothing reads a clock, so the same two files diff to the
// same bytes every time, which is what makes a CI diff over two diff runs
// mean anything.
const (
	// DiffSchema is the diff document's versioned schema name.
	DiffSchema = "aertun/windtunnel-diff/v1"

	DiffRegression = "regression"
	DiffFix        = "fix"
	DiffDrift      = "drift"
	DiffNew        = "new-in-the-later-run"
	DiffRetired    = "ran-only-in-the-earlier-run"
)

// DiffSide is one document's what-ran block, the fields a transition or
// an aggregate delta can be read against.
type DiffSide struct {
	Label        string  `json:"label"`
	Engine       string  `json:"engine"`
	ScoreMode    string  `json:"score_mode"`
	Corpus       string  `json:"corpus"`
	Seed         int64   `json:"seed"`
	Base         string  `json:"base"`
	BaseDigest   string  `json:"base_digest"`
	Pack         string  `json:"pack"`
	PackDigest   string  `json:"pack_digest"`
	Scenarios    int     `json:"scenarios"`
	MustAlert    int     `json:"must_alert_scenarios"`
	Missed       int     `json:"missed"`
	MissRate     float64 `json:"miss_rate"`
	MissRateLow  float64 `json:"miss_rate_wilson_low"`
	MissRateHigh float64 `json:"miss_rate_wilson_high"`
	TwinFires    int     `json:"twin_false_fires"`
	// AmbientFires is what the instrument raised over the base stream
	// alone — the estate's own alerts, before any session was spliced.
	AmbientFires int       `json:"ambient_fires"`
	GeneratedAt  time.Time `json:"generated_at"`
}

// ScenarioDiff is one scenario's transition between two documents, or its
// presence in only one of them.
type ScenarioDiff struct {
	Scenario string `json:"scenario"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Kind     string `json:"kind,omitempty"`
	TwinFrom string `json:"twin_from,omitempty"`
	TwinTo   string `json:"twin_to,omitempty"`
	TwinKind string `json:"twin_kind,omitempty"`
	// Note names what else moved: the scenario's own bytes changing
	// between the documents, which makes its transition a fact about the
	// edit as much as about the controls.
	Note string `json:"note,omitempty"`
}

// AmbientDrift is the calibration statement moving between two runs: the
// base stream alone raised this many alerts then and this many now.
type AmbientDrift struct {
	FromFires int `json:"from_fires"`
	ToFires   int `json:"to_fires"`
	// BaseDigestChanged says whether the two runs even replayed the same
	// bytes — drift over a changed base stream is a fact about the estate,
	// and drift over the same bytes is a fact about the instrument.
	BaseDigestChanged bool `json:"base_digest_changed"`
}

// DiffReport is the whole comparison: what ran on both sides, the
// transitions sorted by scenario id, the counters a gate branches on.
type DiffReport struct {
	Schema string `json:"schema"`
	// Standing is the scoring mode's standing, which both sides share —
	// a diff across modes is refused — so a gate over two self-graded
	// documents says it is one.
	Standing    string         `json:"standing"`
	From        DiffSide       `json:"from"`
	To          DiffSide       `json:"to"`
	Scenarios   []ScenarioDiff `json:"scenarios"`
	Regressions int            `json:"regressions"`
	Fixes       int            `json:"fixes"`
	Drifts      int            `json:"drifts"`
	Ambient     *AmbientDrift  `json:"ambient,omitempty"`
}

// modeOf is a scoring mode's name — the word before the directory or
// file the grammar attaches to it. Two their-Sigma runs over two
// libraries are the same mode (their rules under this engine) with two
// instruments, which is exactly the PR a gate exists to judge; a
// reference run and a their-Sigma run are two modes, which is never a
// transition at all.
func modeOf(scoreMode string) string {
	if i := strings.IndexByte(scoreMode, ':'); i >= 0 {
		return scoreMode[:i]
	}
	return scoreMode
}

// Diff compares two sealed scorecards. The labels are the file names the
// caller read, so a report names what it diffed the way a scorecard names
// what ran.
func Diff(fromLabel string, from *Scorecard, toLabel string,
	to *Scorecard) (*DiffReport, error) {

	if from.Engine != to.Engine {
		return nil, fmt.Errorf("%s names engine %s and %s names %s; a "+
			"scorecard's numbers are only comparable against the engine "+
			"that produced them, and pooling them is the comparison this "+
			"command exists to refuse", fromLabel, from.Engine, toLabel,
			to.Engine)
	}
	if modeOf(from.ScoreMode) != modeOf(to.ScoreMode) {
		return nil, fmt.Errorf("%s scored %s and %s scored %s; the modes "+
			"measure different subjects (the reference pack as the "+
			"calibrated instrument, their own rules under this engine, "+
			"their pipeline's alerts) and are never pooled", fromLabel,
			modeOf(from.ScoreMode), toLabel, modeOf(to.ScoreMode))
	}
	if from.Corpus != to.Corpus {
		return nil, fmt.Errorf("%s ran corpus %s and %s ran %s; the same "+
			"scenario id over different corpus bytes is not a transition, "+
			"it is two different sessions", fromLabel, from.Corpus, toLabel,
			to.Corpus)
	}

	rep := &DiffReport{Schema: DiffSchema, Standing: standingOf(to.ScoreMode),
		From: diffSide(fromLabel, from), To: diffSide(toLabel, to)}

	// The transitions, over the sorted union of scenario ids.
	oldRow := map[string]*Row{}
	for i := range from.Rows {
		oldRow[from.Rows[i].Scenario] = &from.Rows[i]
	}
	newRow := map[string]*Row{}
	for i := range to.Rows {
		newRow[to.Rows[i].Scenario] = &to.Rows[i]
	}
	ids := make([]string, 0, len(oldRow)+len(newRow))
	for id := range oldRow {
		if _, ok := newRow[id]; ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		o, n := oldRow[id], newRow[id]
		d := ScenarioDiff{Scenario: id, From: o.Outcome, To: n.Outcome,
			TwinFrom: o.Twin.Outcome, TwinTo: n.Twin.Outcome}
		if o.Outcome != n.Outcome {
			switch {
			case n.Outcome == OutcomeMissed:
				d.Kind = DiffRegression
				rep.Regressions++
			case o.Outcome == OutcomeMissed:
				d.Kind = DiffFix
				rep.Fixes++
			default:
				d.Kind = DiffDrift
				rep.Drifts++
			}
		}
		if o.Twin.Outcome != n.Twin.Outcome {
			switch {
			case n.Twin.Outcome == TwinFalseFire:
				d.TwinKind = DiffRegression
				rep.Regressions++
			case o.Twin.Outcome == TwinFalseFire:
				d.TwinKind = DiffFix
				rep.Fixes++
			default:
				d.TwinKind = DiffDrift
				rep.Drifts++
			}
		}
		if o.Digest != n.Digest {
			d.Note = fmt.Sprintf("the scenario's bytes changed between "+
				"these documents (%s → %s), so its transition is a fact "+
				"about the edit as much as about the controls",
				shortDigest(o.Digest), shortDigest(n.Digest))
		}
		if d.Kind == "" && d.TwinKind == "" && d.Note == "" {
			continue
		}
		if d.Kind == "" && d.TwinKind == "" {
			// Only the bytes moved; still worth the reader's while.
			d.Kind = DiffDrift
			rep.Drifts++
		}
		rep.Scenarios = append(rep.Scenarios, d)
	}
	for id := range oldRow {
		if _, ok := newRow[id]; ok {
			continue
		}
		rep.Scenarios = append(rep.Scenarios, ScenarioDiff{Scenario: id,
			From: oldRow[id].Outcome, Kind: DiffRetired})
	}
	for id := range newRow {
		if _, ok := oldRow[id]; ok {
			continue
		}
		rep.Scenarios = append(rep.Scenarios, ScenarioDiff{Scenario: id,
			To: newRow[id].Outcome, Kind: DiffNew})
	}
	// The union's tail is map order; re-sort the whole table so the
	// output is the same bytes every time.
	sort.Slice(rep.Scenarios, func(i, j int) bool {
		return rep.Scenarios[i].Scenario < rep.Scenarios[j].Scenario
	})

	// Ambient drift, told apart from rule findings by name.
	if from.AmbientFires != to.AmbientFires ||
		from.BaseDigest != to.BaseDigest {
		rep.Ambient = &AmbientDrift{FromFires: from.AmbientFires,
			ToFires:           to.AmbientFires,
			BaseDigestChanged: from.BaseDigest != to.BaseDigest}
	}
	return rep, nil
}

func diffSide(label string, c *Scorecard) DiffSide {
	a := c.Aggregate
	side := DiffSide{Label: label, Engine: c.Engine, ScoreMode: c.ScoreMode,
		Corpus: c.Corpus, Seed: c.Seed, Base: c.Base,
		BaseDigest: c.BaseDigest, Pack: c.Pack, PackDigest: c.PackDigest,
		AmbientFires: c.AmbientFires, GeneratedAt: c.GeneratedAt}
	if a != nil {
		side.Scenarios = a.Scenarios
		side.MustAlert = a.MustAlert
		side.Missed = a.Missed
		side.MissRate = a.MissRate
		side.MissRateLow = a.MissRateLow
		side.MissRateHigh = a.MissRateHigh
		side.TwinFires = a.TwinFires
	}
	return side
}

// Summarize is the diff in words, deterministic, for a terminal and a CI
// log alike: what ran on both sides, the transitions in scenario order,
// the aggregate with its bounds on both sides, the ambient drift, and the
// verdict a gate branches on.
func (d *DiffReport) Summarize() string {
	var b strings.Builder
	fmt.Fprintf(&b, "wind tunnel diff, engine %s, scoring %s\n", d.From.Engine,
		d.From.ScoreMode)
	fmt.Fprintf(&b, "  scored by %s\n", wrap(standingLine(d.From.ScoreMode)))
	for _, s := range []struct {
		word string
		side DiffSide
	}{{"before", d.From}, {"after", d.To}} {
		fmt.Fprintf(&b, "  %s: %s — base %s (%d scenario(s), missed %d of "+
			"%d must-alert, %d twin false fire(s)), generated %s\n", s.word,
			s.side.Label, s.side.Base, s.side.Scenarios, s.side.Missed,
			s.side.MustAlert, s.side.TwinFires,
			s.side.GeneratedAt.Format(time.RFC3339))
	}
	if len(d.Scenarios) == 0 {
		fmt.Fprintf(&b, "  no scenario transition; the documents' rows "+
			"agree\n")
	}
	for _, s := range d.Scenarios {
		switch s.Kind {
		case DiffNew, DiffRetired:
			outcome := s.To
			if outcome == "" {
				outcome = s.From
			}
			fmt.Fprintf(&b, "    %-38s %s (%s)\n", s.Scenario, s.Kind,
				outcome)
		default:
			// A twin-only transition carries no outcome arrow; the
			// outcome did not move.
			if s.Kind != "" {
				fmt.Fprintf(&b, "    %-38s %s → %s (%s)\n", s.Scenario,
					s.From, s.To, s.Kind)
			} else {
				fmt.Fprintf(&b, "    %-38s outcome held at %s\n", s.Scenario,
					s.From)
			}
		}
		if s.TwinKind != "" {
			fmt.Fprintf(&b, "        twin %s → %s (%s)\n", s.TwinFrom,
				s.TwinTo, s.TwinKind)
		}
		if s.Note != "" {
			fmt.Fprintf(&b, "        %s\n", wrap(s.Note))
		}
	}
	fmt.Fprintf(&b, "  aggregate: missed %d of %d (%s, 95%% Wilson %.1f%% "+
		"to %.1f%%) → missed %d of %d (%s, 95%% Wilson %.1f%% to %.1f%%); "+
		"%d regression(s), %d fix(es), %d drift(s)%s\n",
		d.From.Missed, d.From.MustAlert, pct(d.From.MissRate),
		d.From.MissRateLow*100, d.From.MissRateHigh*100,
		d.To.Missed, d.To.MustAlert, pct(d.To.MissRate),
		d.To.MissRateLow*100, d.To.MissRateHigh*100,
		d.Regressions, d.Fixes, d.Drifts, selfGradedMark(d.From.ScoreMode))
	if d.Ambient != nil {
		why := "the base stream's bytes changed between the runs, so this " +
			"is drift about the estate, not about the rules"
		if !d.Ambient.BaseDigestChanged {
			why = "the base stream's bytes are the same, so the instrument " +
				"changed what it raises on them"
		}
		fmt.Fprintf(&b, "  ambient: %d → %d alert(s) on the base stream "+
			"alone; %s\n", d.Ambient.FromFires, d.Ambient.ToFires,
			wrap(why))
	}
	// The instrument line a their-Sigma PR gate reads first: when the
	// rules themselves changed between the two runs, every transition
	// below is a finding about that change.
	if d.From.PackDigest != "" && d.From.PackDigest != d.To.PackDigest {
		fmt.Fprintf(&b, "  instrument: %s (%s) → %s (%s); the rules that "+
			"ran changed between these documents\n", d.From.Pack,
			shortDigest(d.From.PackDigest), d.To.Pack,
			shortDigest(d.To.PackDigest))
	}
	if d.Regressions > 0 {
		fmt.Fprintf(&b, "  verdict: %d regression(s) — exit 1\n",
			d.Regressions)
	} else {
		fmt.Fprintf(&b, "  verdict: clean, no regression — exit 0\n")
	}
	return b.String()
}
