// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package claim

import (
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/verdict"
)

func card() Card {
	return Card{Name: "charlotte-98", Nonce: strings.Repeat("ab", 16), Source: "charlotte",
		Metric: Agreement, Population: Population{Labels: verdict.People}, Threshold: 0.98,
		Direction: AtLeast, Confidence: 0.95, WindowDays: 30}
}

// A card says exactly what will be tested, or it is refused.
func TestACardSaysExactlyWhatWillBeTested(t *testing.T) {
	if err := card().Validate(); err != nil {
		t.Fatalf("a good card: %v", err)
	}
	for name, change := range map[string]func(*Card){
		"no metric":          func(c *Card) { c.Metric = "accuracy" },
		"no direction":       func(c *Card) { c.Direction = "about" },
		"a certain rate":     func(c *Card) { c.Threshold = 1 },
		"a weak confidence":  func(c *Card) { c.Confidence = 0.3 },
		"an endless window":  func(c *Card) { c.WindowDays = 4000 },
		"no labels":          func(c *Card) { c.Population.Labels = "" },
		"a free-text filter": func(c *Card) { c.Population.MinSeverity = "the bad ones" },
		"a blind metric with labels": func(c *Card) {
			c.Metric = AdjudicatedFalseClosures
		},
	} {
		c := card()
		change(&c)
		if c.Validate() == nil {
			t.Errorf("%s: validated", name)
		}
	}
}

// Nothing is decided before the window closes; after it, the bound on the
// claimed side decides, and a handful of alerts proves nothing.
func TestACardIsDecidedOnlyWhenItsWindowHasClosed(t *testing.T) {
	c := card()
	strong := verdict.Count{K: 995, N: 1000}
	if o := c.Evaluate(strong, false); o.Holds || o.Fails {
		t.Errorf("decided before the window closed: %+v", o)
	}
	if o := c.Evaluate(strong, true); !o.Holds || o.Fails {
		t.Errorf("995 of 1000 against at least 0.98: %+v", o)
	}
	if o := c.Evaluate(verdict.Count{K: 900, N: 1000}, true); o.Holds || !o.Fails {
		t.Errorf("900 of 1000 against at least 0.98: %+v", o)
	}
	if o := c.Evaluate(verdict.Count{K: 29, N: 29}, true); o.Holds {
		t.Errorf("29 of 29 proved a claim: %+v", o)
	}
}

// A card is tested against its one registration; one edited since matches
// none.
func TestACardEditedAfterRegisteringMatchesNoRegistration(t *testing.T) {
	c := card()
	ev := []audit.Event{{Seq: 1, Action: RegisteredAction, At: "2026-11-01T09:00:00Z",
		Detail: c.RegisterDetail()}}
	// A chain of one hand-made event does not verify; the digest rule is
	// what this test is about, so it is read from the detail directly.
	edited := c
	edited.Threshold = 0.9
	if edited.Digest() == c.Digest() {
		t.Fatal("changing the threshold did not change the digest")
	}
	if ev[0].Detail["sha256"] != c.Digest() || ev[0].Detail["sha256"] == edited.Digest() {
		t.Error("the registration does not commit to the card's terms")
	}
}
