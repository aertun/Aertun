// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package adjudicate

import (
	"fmt"

	"github.com/aertun/aertun/internal/stats"
)

// How many closures to review.
//
// A team that wants to say "fewer than one closure in a hundred is wrong,
// at 95%" needs enough reviewed closures that the exact upper bound on the
// false-closure rate falls below 1% given what the review finds. With no
// failures found that is n = ln(1−confidence) / ln(1−rate), rounded up —
// 299 for 1% at 95% — and with failures the bound is searched for with the
// same exact bound the proof reports.

// MaxSize is the largest sample this will recommend; a target that needs
// more is one no review by hand will meet.
const MaxSize = 10_000_000

// Size is the smallest number of reviewed closures per stratum whose
// one-sided exact upper bound at confidence is at most rate, if failures of
// them are judged real.
func Size(rate, confidence float64, failures int) (int, error) {
	if !(rate > 0 && rate < 1) || !(confidence > 0 && confidence < 1) {
		return 0, fmt.Errorf("the rate and the confidence are each strictly between 0 and 1")
	}
	if failures < 0 {
		return 0, fmt.Errorf("the number of failures cannot be negative")
	}
	fits := func(n int) bool { return stats.ClopperPearsonUpper(failures, n, confidence) <= rate }
	lo := failures + 1
	if fits(lo) {
		return lo, nil
	}
	hi := lo
	for !fits(hi) {
		if hi >= MaxSize {
			return 0, fmt.Errorf("no sample of up to %d holds the rate under %v at %v with %d failures",
				MaxSize, rate, confidence, failures)
		}
		lo, hi = hi, min(hi*2, MaxSize)
	}
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		if fits(mid) {
			hi = mid
		} else {
			lo = mid
		}
	}
	return hi, nil
}
