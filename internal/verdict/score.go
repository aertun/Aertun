// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package verdict

import (
	"sort"
	"time"

	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/telemetry"
)

// Scoring: each vendor verdict joined to the person's disposition of the
// same alert, and counted.
//
// # Where the disposition comes from
//
// Two places, never mixed in one score, and the score says which:
//
//   - People: a decision a verified person recorded in this program on the
//     finding that carries the alert's key. A detection run puts the
//     platform's own id for an alert on the evidence it raises
//     (finding.Evidence.Alert, from the event's telemetry.AlertField), and that
//     is the link: the vendor's AI and this program's rules looked at the
//     same alert, and the person decided the finding. The label is the
//     state of the last decision a verified person made on it — triaged,
//     accepted and fixed say it was real — and a finding whose last such
//     decision is open or stale has no disposition yet.
//   - Reported: the disposition column of the vendor's own export. The
//     vendor says what the person decided, and nothing here can check it,
//     which is why it is labelled source-reported wherever it is used.
//
// # The order rule
//
// A verdict counts only if it was given before the disposition: before the
// first decision anybody recorded on the finding — verified or not, because
// a vendor that learns from the analyst learns from whatever the analyst
// did — or before the reported disposition's own time. Everything is read
// as it stood at the end of the period, so a score over a closed period
// does not move when somebody decides more later.
//
// # The unit
//
// Rates are per alert. An alert the AI answered several times is scored by
// the last answer it gave before the disposition — its standing answer when
// the person decided — and the answers' agreement with each other is
// counted separately, as consistency.

// LabelSource says where the dispositions came from.
type LabelSource string

const (
	// People are decisions verified people recorded here.
	People LabelSource = proof.LabelsPeople
	// Reported are dispositions the vendor's export reports.
	Reported LabelSource = proof.LabelsReported
)

// Known reports whether l is a label source.
func (l LabelSource) Known() bool { return l == People || l == Reported }

// Reason is why a verdict was not counted.
type Reason string

// The reasons are the closed set a verdicts proof names (internal/proof),
// so a reason counted here is one a proof can carry.
const (
	BeforeRegistration Reason = proof.ExcludedBeforeRegistration
	AfterDisposition   Reason = proof.ExcludedAfterDisposition
	Unlinked           Reason = proof.ExcludedUnlinked
	Ambiguous          Reason = proof.ExcludedAmbiguous
	Undecided          Reason = proof.ExcludedUndecided
	NoVerifiedDecision Reason = proof.ExcludedNoVerifiedDecision
	Conflicting        Reason = proof.ExcludedConflicting
	OutsidePopulation  Reason = proof.ExcludedOutsidePopulation
)

// Reasons lists every reason, in the order a reader meets them.
func Reasons() []Reason {
	var out []Reason
	for _, r := range proof.ExclusionReasons() {
		out = append(out, Reason(r))
	}
	return out
}

// Count is k of n.
type Count = proof.Count

// Input is everything a score is computed from.
type Input struct {
	Source string
	// Since and Until bound when verdicts were given; the store is read as
	// it stood at Until.
	Since, Until time.Time
	// After, when set, is when a claim was registered: a verdict given or
	// delivered before it is not counted.
	After  time.Time
	Labels LabelSource
	// Verdicts are every stored verdict; the score takes Source's.
	Verdicts []Verdict
	// Findings, Decisions and People are read for People labels: the
	// register, every decision recorded on any finding, and those of them
	// made by verified people.
	Findings  []finding.Finding
	Decisions []finding.Decision
	People    []finding.Decision
	// MinSeverity, when set, keeps alerts whose finding is at least this
	// severe.
	MinSeverity telemetry.Severity
}

// Score is the outcome.
type Score struct {
	// Considered are Source's verdicts given in the period, every one of
	// which is either counted or excluded with a reason.
	Considered []Verdict
	Counted    int
	Excluded   map[Reason]int
	// Alerts are the alerts with at least one counted verdict.
	Alerts int
	// Agreement is standing answers that were a disposition and matched
	// the person's; FalseClosures is closing answers on alerts the person
	// found real; EscalationsClosed is escalations the person closed;
	// Abstentions is abstaining answers among all alerts; Consistency is
	// alerts answered more than once whose answers all agreed.
	Agreement, FalseClosures, EscalationsClosed, Abstentions, Consistency Count
	// FalseClosed are the keys of the falsely closed alerts, sorted.
	FalseClosed []string
	// ReviewCoverage is the closures a person decided (FalseClosures.N) of
	// every alert the product's standing answer closed that a disposition
	// could have been looked up for: the counted ones, and those excluded
	// as undecided or decided by nobody verified. DeliveredFirst is the
	// counted verdicts this program received before the disposition, of all
	// counted: the ones whose order does not rest on the product's clock.
	ReviewCoverage, DeliveredFirst Count
}

// FromState is the disposition a finding's state records, or "" for a
// state that is not one.
func FromState(s finding.State) Word {
	switch s {
	case finding.Triaged, finding.Accepted, finding.Fixed:
		return Real
	case finding.FalsePositive:
		return FalsePositive
	case finding.Benign:
		return Benign
	}
	return ""
}

// Index maps each alert key to the detection findings whose evidence
// carries it.
func Index(findings []finding.Finding) map[string][]finding.Finding {
	out := map[string][]finding.Finding{}
	for _, f := range findings {
		if f.Kind != finding.FromDetection {
			continue
		}
		seen := map[string]bool{}
		for _, e := range f.Evidence {
			if ValidAlert(e.Alert) && !seen[e.Alert] {
				seen[e.Alert] = true
				out[e.Alert] = append(out[e.Alert], f)
			}
		}
	}
	return out
}

// ordered sorts decisions the way finding.Apply folds them.
func ordered(ds []finding.Decision) []finding.Decision {
	out := append([]finding.Decision(nil), ds...)
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.Before(out[j].At)
		}
		return out[i].To < out[j].To
	})
	return out
}

// Decided is what the decisions say about one finding before a moment:
// when anybody first recorded anything, and the disposition in the last
// decision a verified person made.
type Decided struct {
	First  time.Time
	Last   Word
	Anyone bool
	Person bool
}

// DecidedBefore reads one finding's decisions as they stood at before.
func DecidedBefore(id string, all, people []finding.Decision, before time.Time) Decided {
	var d Decided
	for _, x := range ordered(all) {
		if x.Finding == id && x.At.Before(before) {
			d.First, d.Anyone = x.At, true
			break
		}
	}
	for _, x := range ordered(people) {
		if x.Finding == id && x.At.Before(before) {
			d.Last, d.Person = FromState(x.To), true
		}
	}
	return d
}

// Compute scores Source's verdicts.
func Compute(in Input) Score {
	s := Score{Excluded: map[Reason]int{}}
	byAlert := map[string][]Verdict{}
	var keys []string
	for _, v := range in.Verdicts {
		if v.Source != in.Source || v.At.Before(in.Since) || !v.At.Before(in.Until) ||
			!v.Imported.Before(in.Until) {
			continue
		}
		s.Considered = append(s.Considered, v)
		if !in.After.IsZero() && (v.At.Before(in.After) || v.Imported.Before(in.After)) {
			s.Excluded[BeforeRegistration]++
			continue
		}
		if _, ok := byAlert[v.Alert]; !ok {
			keys = append(keys, v.Alert)
		}
		byAlert[v.Alert] = append(byAlert[v.Alert], v)
	}
	sortVerdicts(s.Considered)
	sort.Strings(keys)

	var index map[string][]finding.Finding
	if in.Labels == People {
		index = Index(in.Findings)
	}
	for _, key := range keys {
		vs := byAlert[key]
		sortVerdicts(vs)
		label, cutoff, why := disposition(in, index, key, vs)
		if why != "" {
			s.Excluded[why] += len(vs)
			if (why == Undecided || why == NoVerifiedDecision) && vs[len(vs)-1].Says.Closes() {
				// Closed by the product, and never decided: the closures
				// the rate does not see.
				s.ReviewCoverage.N++
			}
			continue
		}
		var counted []Verdict
		for _, v := range vs {
			if v.At.Before(cutoff) {
				counted = append(counted, v)
				s.DeliveredFirst.N++
				if v.Imported.Before(cutoff) {
					s.DeliveredFirst.K++
				}
			} else {
				s.Excluded[AfterDisposition]++
			}
		}
		if len(counted) == 0 {
			continue
		}
		s.Counted += len(counted)
		s.Alerts++
		standing := counted[len(counted)-1].Says
		s.Abstentions.N++
		switch {
		case standing == Abstain:
			s.Abstentions.K++
		case standing == Escalate:
			s.EscalationsClosed.N++
			if label.Closes() {
				s.EscalationsClosed.K++
			}
		default:
			s.Agreement.N++
			if standing == label {
				s.Agreement.K++
			}
			if standing.Closes() {
				s.FalseClosures.N++
				s.ReviewCoverage.K++
				s.ReviewCoverage.N++
				if label == Real {
					s.FalseClosures.K++
					s.FalseClosed = append(s.FalseClosed, key)
				}
			}
		}
		if len(counted) > 1 {
			s.Consistency.N++
			same := true
			for _, v := range counted[1:] {
				same = same && v.Says == counted[0].Says
			}
			if same {
				s.Consistency.K++
			}
		}
	}
	return s
}

// disposition is the label an alert is scored against and the moment a
// verdict must precede, or the reason it has none.
func disposition(in Input, index map[string][]finding.Finding, key string,
	vs []Verdict) (Word, time.Time, Reason) {

	if in.Labels == Reported {
		var label Word
		var cutoff time.Time
		for _, v := range vs {
			if v.Reported == "" || !v.ReportedAt.Before(in.Until) {
				continue
			}
			if label != "" && v.Reported != label {
				return "", time.Time{}, Conflicting
			}
			label = v.Reported
			if cutoff.IsZero() || v.ReportedAt.Before(cutoff) {
				cutoff = v.ReportedAt
			}
		}
		if label == "" {
			return "", time.Time{}, Undecided
		}
		return label, cutoff, ""
	}
	fs := index[key]
	switch {
	case len(fs) == 0:
		return "", time.Time{}, Unlinked
	case len(fs) > 1:
		return "", time.Time{}, Ambiguous
	}
	f := fs[0]
	if in.MinSeverity > 0 && f.Severity < in.MinSeverity {
		return "", time.Time{}, OutsidePopulation
	}
	d := DecidedBefore(f.ID, in.Decisions, in.People, in.Until)
	switch {
	case !d.Anyone:
		return "", time.Time{}, Undecided
	case !d.Person:
		return "", time.Time{}, NoVerifiedDecision
	case d.Last == "":
		return "", time.Time{}, Undecided
	}
	return d.Last, d.First, ""
}

// sortVerdicts orders verdicts by when they were given, then by alert and
// word, so the same store always scores the same way.
func sortVerdicts(vs []Verdict) {
	rank := map[Word]int{}
	for i, w := range Words() {
		rank[w] = i
	}
	sort.SliceStable(vs, func(i, j int) bool {
		a, b := vs[i], vs[j]
		if !a.At.Equal(b.At) {
			return a.At.Before(b.At)
		}
		if a.Alert != b.Alert {
			return a.Alert < b.Alert
		}
		return rank[a.Says] < rank[b.Says]
	})
}
