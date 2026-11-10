// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package stats

import "math"

// The exact binomial interval, for claims that must hold rather than
// approximately hold.
//
// Wilson is the interval to show beside a rate: it is centred sensibly and
// short, and it is an approximation. A number somebody is going to act on
// as a guarantee ("false closures stay under 2%") is bounded by
// Clopper–Pearson instead, which inverts the binomial distribution itself,
// so by construction it covers at least the stated confidence whatever the
// true rate is. The price is width, and that is the right price for a
// guarantee.
//
// Everything is computed from the regularised incomplete beta function in
// pure Go: the binomial tail P(X ≤ k) for n trials at rate p is
// I_{1−p}(n−k, k+1), and the bound is the rate at which that tail equals
// the risk allowed, found by bisection. Bisection rather than a Newton
// step because the tail is monotone in p and bisection cannot overshoot:
// the bound returned is always the side of the root that keeps the
// guarantee.

// ClopperPearson is the exact two-sided interval for k successes in n
// trials at the given confidence (e.g. 0.95); n == 0 gives (0, 1).
//
// A confidence outside (0, 1) gives (0, 1) as well: an interval that
// claims nothing is the only honest answer to a question that cannot be
// asked.
func ClopperPearson(k, n int, confidence float64) (low, high float64) {
	if n <= 0 || !(confidence > 0 && confidence < 1) {
		return 0, 1
	}
	k = min(max(k, 0), n)
	tail := (1 - confidence) / 2
	low, high = 0, 1
	if k > 0 {
		// The rate at which k or more successes are as unlikely as the
		// lower tail allows: P(X ≥ k) = tail, so P(X ≤ k−1) = 1 − tail.
		low = solveTail(k-1, n, 1-tail, false)
	}
	if k < n {
		high = solveTail(k, n, tail, true)
	}
	return low, high
}

// ClopperPearsonUpper is the exact one-sided upper bound on the rate behind
// k successes in n trials, at the given confidence: the true rate is at or
// under it with at least that probability. n == 0, k == n, or a confidence
// outside (0, 1) gives 1, which bounds nothing.
func ClopperPearsonUpper(k, n int, confidence float64) float64 {
	if n <= 0 || !(confidence > 0 && confidence < 1) {
		return 1
	}
	k = min(max(k, 0), n)
	if k == n {
		return 1
	}
	return solveTail(k, n, 1-confidence, true)
}

// solveTail finds the rate p at which BinomialCDF(k, n, p) equals target.
// The tail falls as p rises, so the root is bracketed by [0, 1] and
// bisection keeps it bracketed. upper says which end of the final bracket
// to return: the high end for an upper bound and the low end for a lower
// one, so rounding always widens the interval rather than narrowing it.
func solveTail(k, n int, target float64, upper bool) float64 {
	lo, hi := 0.0, 1.0
	for i := 0; i < 200 && hi-lo > 1e-15; i++ {
		mid := (lo + hi) / 2
		if BinomialCDF(k, n, mid) > target {
			lo = mid
		} else {
			hi = mid
		}
	}
	if upper {
		return hi
	}
	return lo
}

// BinomialCDF is P(X ≤ k) for X binomial with n trials at rate p.
func BinomialCDF(k, n int, p float64) float64 {
	switch {
	case k < 0:
		return 0
	case k >= n:
		return 1
	case p <= 0:
		return 1
	case p >= 1:
		return 0
	}
	return RegIncBeta(float64(n-k), float64(k+1), 1-p)
}

// RegIncBeta is the regularised incomplete beta function I_x(a, b), for
// a, b > 0 and x in [0, 1]; NaN outside that domain.
//
// It is the standard continued fraction for the incomplete beta function,
// evaluated by the modified Lentz method, applied on whichever side of the
// mean it converges fast and reflected through I_x(a, b) = 1 − I_{1−x}(b, a)
// on the other.
func RegIncBeta(a, b, x float64) float64 {
	switch {
	case math.IsNaN(a) || math.IsNaN(b) || math.IsNaN(x) || a <= 0 || b <= 0 ||
		x < 0 || x > 1:
		return math.NaN()
	case x == 0:
		return 0
	case x == 1:
		return 1
	}
	lab, _ := math.Lgamma(a + b)
	la, _ := math.Lgamma(a)
	lb, _ := math.Lgamma(b)
	front := math.Exp(lab - la - lb + a*math.Log(x) + b*math.Log1p(-x))
	if x < (a+1)/(a+b+2) {
		return front * betaFraction(a, b, x) / a
	}
	return 1 - front*betaFraction(b, a, 1-x)/b
}

// betaFraction evaluates the incomplete beta continued fraction. It
// converges in O(√max(a, b)) terms on the side RegIncBeta calls it from;
// the cap is far beyond what any count here reaches.
func betaFraction(a, b, x float64) float64 {
	const (
		eps  = 1e-16
		tiny = 1e-300
	)
	qab, qap, qam := a+b, a+1, a-1
	c := 1.0
	d := 1 - qab*x/qap
	if math.Abs(d) < tiny {
		d = tiny
	}
	d = 1 / d
	h := d
	for m := 1; m <= 100000; m++ {
		mf := float64(m)
		m2 := 2 * mf
		aa := mf * (b - mf) * x / ((qam + m2) * (a + m2))
		d = 1 + aa*d
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = 1 + aa/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		h *= d * c
		aa = -(a + mf) * (qab + mf) * x / ((a + m2) * (qap + m2))
		d = 1 + aa*d
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = 1 + aa/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		del := d * c
		h *= del
		if math.Abs(del-1) < eps {
			break
		}
	}
	return h
}
