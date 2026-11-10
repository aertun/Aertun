// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/stats"
	"github.com/aertun/aertun/internal/telemetry"
)

// What the proofs about other vendors' AI share: a rate always stated as
// its exact counts beside its bounds, and the closed set of reasons a
// verdict was not counted.
//
// The bounds are recomputed from the counts when a statement is validated,
// on signing and on opening, so a proof whose interval does not follow from
// its own k and n is refused rather than believed.
//
// This package owns those shapes and words; internal/verdict, which does the
// counting, takes them from here. A proof is the thing a stranger checks, so
// what it may say is decided where it is checked.

// MinSample is the fewest items a proven verdict may rest on, whatever the
// tolerance. An exact bound already widens as the sample shrinks, so this is
// a floor under it rather than the test itself: with a generous tolerance a
// handful of closures could clear the bound, and a proof over a handful is
// not one anybody should read as a measurement of a product.
const MinSample = 30

// Confidence is the level the rates in these proofs are bounded at.
const Confidence = 0.95

// Rate is k of n with its 95% Wilson interval: a measurement reported
// beside a verdict rather than one a verdict turns on.
type Rate struct {
	K    int     `json:"k"`
	N    int     `json:"n"`
	Low  float64 `json:"low"`
	High float64 `json:"high"`
}

// WilsonRate is k of n with its interval.
func WilsonRate(k, n int) Rate {
	lo, hi := stats.Wilson(k, n)
	return Rate{K: k, N: n, Low: lo, High: hi}
}

func (r Rate) valid() bool {
	if r.K < 0 || r.N < 0 || r.K > r.N {
		return false
	}
	want := WilsonRate(r.K, r.N)
	return approx(r.Low, want.Low) && approx(r.High, want.High)
}

// Bound is k of n with the exact one-sided bounds at Confidence on each
// side: Lower is the rate the truth is at or over, Upper the rate it is at
// or under, each with at least that probability. A tolerance is read
// against them — over it is shown by Lower, under it by Upper — so each
// conclusion a proof draws is wrong at most 5% of the time.
type Bound struct {
	K     int     `json:"k"`
	N     int     `json:"n"`
	Lower float64 `json:"lower"`
	Upper float64 `json:"upper"`
}

// ExactBound is k of n with its exact one-sided bounds.
func ExactBound(k, n int) Bound {
	b := Bound{K: k, N: n, Lower: 0, Upper: stats.ClopperPearsonUpper(k, n, Confidence)}
	if n > 0 && k > 0 {
		// The lower bound on the rate of k is one minus the upper bound
		// on the rate of the n−k that are not.
		b.Lower = 1 - stats.ClopperPearsonUpper(n-k, n, Confidence)
	}
	return b
}

func (b Bound) valid() bool {
	if b.K < 0 || b.N < 0 || b.K > b.N {
		return false
	}
	want := ExactBound(b.K, b.N)
	return approx(b.Lower, want.Lower) && approx(b.Upper, want.Upper)
}

func approx(a, b float64) bool { return math.Abs(a-b) <= 1e-9 }

func unit(f float64) bool { return f >= 0 && f <= 1 }

// validTolerance is a rate somebody could hold a product to: more than none,
// because no finite sample shows a rate of exactly zero, and less than all.
func validTolerance(t float64) bool { return t > 0 && t < 1 && !math.IsNaN(t) }

// The reasons a vendor's verdict is not counted, in the order a reader
// meets them.
const (
	// ExcludedBeforeRegistration: given or delivered before the claim it
	// would count towards was registered.
	ExcludedBeforeRegistration = "before-registration"
	// ExcludedAfterDisposition: given at or after the disposition, so not
	// independent of it.
	ExcludedAfterDisposition = "after-disposition"
	// ExcludedUnlinked: no finding carries the alert's id.
	ExcludedUnlinked = "unlinked"
	// ExcludedAmbiguous: more than one finding carries it.
	ExcludedAmbiguous = "ambiguous"
	// ExcludedUndecided: nobody has given the alert a disposition.
	ExcludedUndecided = "undecided"
	// ExcludedNoVerifiedDecision: decided, by nobody whose identity was
	// proved.
	ExcludedNoVerifiedDecision = "no-verified-decision"
	// ExcludedConflicting: the export reports different dispositions for
	// one alert.
	ExcludedConflicting = "conflicting-reports"
	// ExcludedOutsidePopulation: the alert's finding is below the severity
	// asked for.
	ExcludedOutsidePopulation = "outside-population"
)

// ExclusionReasons lists every reason.
func ExclusionReasons() []string {
	return []string{ExcludedBeforeRegistration, ExcludedAfterDisposition, ExcludedUnlinked,
		ExcludedAmbiguous, ExcludedUndecided, ExcludedNoVerifiedDecision, ExcludedConflicting,
		ExcludedOutsidePopulation}
}

// Exclusion is how many verdicts were not counted, and the closed-set
// reason why.
type Exclusion struct {
	Reason   string `json:"reason"`
	Verdicts int    `json:"verdicts"`
}

// Exclusions lists m's reasons in their order, leaving out those with none.
func Exclusions(m map[string]int) []Exclusion {
	out := []Exclusion{}
	for _, r := range ExclusionReasons() {
		if n := m[r]; n > 0 {
			out = append(out, Exclusion{Reason: r, Verdicts: n})
		}
	}
	return out
}

// excludedTotal checks a list of exclusions and adds them up.
func excludedTotal(ex []Exclusion) (int, error) {
	order := map[string]int{}
	for i, r := range ExclusionReasons() {
		order[r] = i + 1
	}
	total, last := 0, 0
	for _, e := range ex {
		at := order[e.Reason]
		if at == 0 || at <= last || e.Verdicts <= 0 {
			return 0, fmt.Errorf("an exclusion names a reason this version does not have, " +
				"out of order or twice, or with no verdicts")
		}
		last = at
		total += e.Verdicts
	}
	return total, nil
}

// A vendor's product is named by a short name the operator chose: never the
// vendor's own wording, which is theirs to put anything in.
var sourceShape = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// ValidVerdictSource reports whether s can name a vendor's product.
func ValidVerdictSource(s string) bool { return sourceShape.MatchString(s) }

func validPeriod(since, until string) bool {
	a, err1 := time.Parse(time.RFC3339, since)
	b, err2 := time.Parse(time.RFC3339, until)
	return err1 == nil && err2 == nil && a.Before(b)
}

// alertFailure is how a verdicts proof names a false closure: the closed
// phrase and the alert's id in the only shape an alert id is kept in.
func alertFailure(id string) string { return "false closure: " + id }

func validAlertFailure(s string) bool {
	id, ok := strings.CutPrefix(s, "false closure: ")
	return ok && telemetry.ValidAlertID(id)
}

func day(t time.Time) string { return t.UTC().Format(time.RFC3339) }
