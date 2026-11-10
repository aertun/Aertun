// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"math"
	"testing"
)

// binomSum is P(X ≤ k) summed term by term from the binomial pmf in log
// space: a second derivation of the tail that shares nothing with
// RegIncBeta, so the bounds below are checked against the definition rather
// than against the function that computed them.
func binomSum(k, n int, p float64) float64 {
	total := 0.0
	for i := 0; i <= k; i++ {
		ln, _ := math.Lgamma(float64(n + 1))
		li, _ := math.Lgamma(float64(i + 1))
		lr, _ := math.Lgamma(float64(n - i + 1))
		total += math.Exp(ln - li - lr + float64(i)*math.Log(p) +
			float64(n-i)*math.Log1p(-p))
	}
	return total
}

// The regularised incomplete beta function against values that follow from
// its definition: I_x(1, 1) = x, I_x(a, 1) = x^a, I_x(1, b) = 1 − (1−x)^b,
// I_½(a, a) = ½ by symmetry, and for whole a and b,
// I_x(a, b) = P(Binomial(a+b−1, x) ≥ a) — I_0.4(2, 3) is
// 1 − 0.6⁴ − 4·0.4·0.6³ = 0.5248.
func TestRegIncBetaMatchesItsClosedForms(t *testing.T) {
	for _, c := range []struct{ a, b, x, want float64 }{
		{1, 1, 0.37, 0.37},
		{3.5, 1, 0.8, math.Pow(0.8, 3.5)},
		{1, 7, 0.15, 1 - math.Pow(0.85, 7)},
		{12.5, 12.5, 0.5, 0.5},
		{400, 400, 0.5, 0.5},
		{2, 3, 0.4, 0.5248},
		{2, 3, 0, 0},
		{2, 3, 1, 1},
	} {
		if got := RegIncBeta(c.a, c.b, c.x); math.Abs(got-c.want) > 1e-12 {
			t.Errorf("I_%v(%v, %v) = %v, want %v", c.x, c.a, c.b, got, c.want)
		}
	}
	for _, bad := range [][3]float64{{0, 1, 0.5}, {1, -1, 0.5}, {1, 1, 1.5}, {math.NaN(), 1, 0.5}} {
		if got := RegIncBeta(bad[0], bad[1], bad[2]); !math.IsNaN(got) {
			t.Errorf("I_%v(%v, %v) outside the domain = %v, want NaN", bad[2], bad[0], bad[1], got)
		}
	}
}

// Values with no closed form, as computed by SciPy 1.16
// (scipy.special.betainc), which anybody can reproduce.
func TestRegIncBetaMatchesAReferenceImplementation(t *testing.T) {
	for _, c := range []struct{ a, b, x, want float64 }{
		{0.5, 0.5, 0.3, 0.36901011956554536},
		{10, 20, 0.25, 0.16630494959787945},
		{100, 200, 0.35, 0.7325714649575445},
		{1.5, 7.25, 0.1, 0.3357217158432781},
		{30, 1, 0.97, 0.40100706854315743},
	} {
		if got := RegIncBeta(c.a, c.b, c.x); math.Abs(got-c.want) > 1e-12 {
			t.Errorf("I_%v(%v, %v) = %v, SciPy gives %v", c.x, c.a, c.b, got, c.want)
		}
	}
}

// The closed forms published for the interval's ends: "when x=0 the
// interval is (0, 1−(α/2)^(1/n)) and when x=n it is ((α/2)^(1/n), 1)"
// (https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval,
// revision 1374408093, Clopper–Pearson section). The one-sided bound at
// x = 0 is the same expression with the whole of α in one tail.
func TestClopperPearsonMatchesThePublishedClosedForms(t *testing.T) {
	for _, n := range []int{1, 3, 10, 59, 300, 5000} {
		for _, conf := range []float64{0.9, 0.95, 0.99} {
			alpha := 1 - conf
			lo, hi := ClopperPearson(0, n, conf)
			if want := 1 - math.Pow(alpha/2, 1/float64(n)); lo != 0 || math.Abs(hi-want) > 1e-12 {
				t.Errorf("ClopperPearson(0, %d, %v) = [%v, %v], want [0, %v]", n, conf, lo, hi, want)
			}
			lo, hi = ClopperPearson(n, n, conf)
			if want := math.Pow(alpha/2, 1/float64(n)); hi != 1 || math.Abs(lo-want) > 1e-12 {
				t.Errorf("ClopperPearson(%d, %d, %v) = [%v, %v], want [%v, 1]", n, n, conf, lo, hi, want)
			}
			if got, want := ClopperPearsonUpper(0, n, conf), 1-math.Pow(alpha, 1/float64(n)); math.Abs(got-want) > 1e-12 {
				t.Errorf("ClopperPearsonUpper(0, %d, %v) = %v, want %v", n, conf, got, want)
			}
		}
	}
}

// Bounds in the middle of the range, as computed by SciPy 1.16 from the
// beta-quantile form of the same interval (scipy.stats.beta.ppf(q, k+1,
// n−k) for an upper end, ppf(q, k, n−k+1) for a lower one), and each one
// also checked against its definition by summing the binomial directly.
func TestClopperPearsonMatchesAReferenceImplementation(t *testing.T) {
	upper := []struct {
		k, n       int
		conf, want float64
	}{
		{1, 10, 0.95, 0.39416330243650466},
		{5, 10, 0.975, 0.8129139715526015},
		{2, 100, 0.95, 0.06161920039604069},
		{3, 50, 0.99, 0.18720925616529482},
		{10, 1000, 0.95, 0.016903175120562504},
		{49, 50, 0.95, 0.9989746601327679},
		{7, 300, 0.999, 0.06405552752366474},
		{0, 135, 1 - 0.05/51, 0.05002085166568506},
	}
	for _, c := range upper {
		got := ClopperPearsonUpper(c.k, c.n, c.conf)
		if math.Abs(got-c.want) > 1e-10 {
			t.Errorf("ClopperPearsonUpper(%d, %d, %v) = %v, SciPy gives %v", c.k, c.n, c.conf, got, c.want)
		}
		// The definition: at the bound, k or fewer successes are exactly
		// as likely as the risk allowed.
		if tail := binomSum(c.k, c.n, got); math.Abs(tail-(1-c.conf)) > 1e-9 {
			t.Errorf("at the bound %v, P(X ≤ %d) = %v, want %v", got, c.k, tail, 1-c.conf)
		}
	}
	two := []struct {
		k, n         int
		conf, lo, hi float64
	}{
		{682, 925, 0.95, 0.7076682640790388, 0.7654065582415253},
		{3, 10, 0.95, 0.06673951117773447, 0.6524528500599973},
		{1, 20, 0.95, 0.0012650894979498038, 0.24873276277202777},
	}
	for _, c := range two {
		lo, hi := ClopperPearson(c.k, c.n, c.conf)
		if math.Abs(lo-c.lo) > 1e-10 || math.Abs(hi-c.hi) > 1e-10 {
			t.Errorf("ClopperPearson(%d, %d, %v) = [%v, %v], SciPy gives [%v, %v]",
				c.k, c.n, c.conf, lo, hi, c.lo, c.hi)
		}
		half := (1 - c.conf) / 2
		if tail := 1 - binomSum(c.k-1, c.n, lo); math.Abs(tail-half) > 1e-9 {
			t.Errorf("at the lower end %v, P(X ≥ %d) = %v, want %v", lo, c.k, tail, half)
		}
		if tail := binomSum(c.k, c.n, hi); math.Abs(tail-half) > 1e-9 {
			t.Errorf("at the upper end %v, P(X ≤ %d) = %v, want %v", hi, c.k, tail, half)
		}
	}
}

// No evidence bounds nothing, and neither does a question with no
// confidence in it. The bound never rounds to the side that would break
// the guarantee.
func TestClopperPearsonClaimsNothingWithoutEvidence(t *testing.T) {
	if lo, hi := ClopperPearson(0, 0, 0.95); lo != 0 || hi != 1 {
		t.Errorf("no trials gave [%v, %v]", lo, hi)
	}
	if got := ClopperPearsonUpper(0, 0, 0.95); got != 1 {
		t.Errorf("no trials gave an upper bound of %v", got)
	}
	for _, conf := range []float64{0, 1, -0.5, 1.5, math.NaN()} {
		if lo, hi := ClopperPearson(3, 10, conf); lo != 0 || hi != 1 {
			t.Errorf("confidence %v gave [%v, %v]", conf, lo, hi)
		}
		if got := ClopperPearsonUpper(3, 10, conf); got != 1 {
			t.Errorf("confidence %v gave an upper bound of %v", conf, got)
		}
	}
	for _, c := range []struct{ k, n int }{{0, 7}, {2, 9}, {40, 400}} {
		// Judged by the tail the bisection itself evaluates: the end it
		// returns is one where k or fewer successes are no more likely
		// than the risk allowed, never one just short of it.
		got := ClopperPearsonUpper(c.k, c.n, 0.95)
		if BinomialCDF(c.k, c.n, got) > 0.05 {
			t.Errorf("the bound for %d of %d rounded below the root", c.k, c.n)
		}
	}
	if lo, hi := ClopperPearson(12, 10, 0.95); lo <= 0 || hi != 1 {
		t.Errorf("more successes than trials is read as all of them: [%v, %v]", lo, hi)
	}
}
