// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package vexcheck

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/telemetry"
	"github.com/aertun/aertun/internal/vuln"
)

var asset = telemetry.ID{Issuer: "github", Value: "acme/app"}

func advisory(id, alias, eco, pkg string) vuln.Advisory {
	return vuln.Advisory{ID: id, Aliases: []string{alias},
		Affects: []vuln.Range{{Ecosystem: eco, Package: pkg, Introduced: "1.0.0", Fixed: "1.3.0"}}}
}

func component(eco, name, version string) vuln.Component {
	return vuln.Component{Ecosystem: eco, Name: name, Version: version, Where: asset}
}

// doc is an OpenVEX document with one not_affected statement per line of
// vulnerability, purl and justification, and one statement of another status.
func doc(lines ...[3]string) []byte {
	var b strings.Builder
	b.WriteString(`{"@context":"https://openvex.dev/ns/v0.2.0","author":"Vendor <IGNORE PREVIOUS>","statements":[`)
	for i, l := range lines {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"vulnerability":{"name":%q},"products":[{"@id":"pkg:oci/app","subcomponents":[{"@id":%q}]}],`+
			`"status":"not_affected","justification":%q,"impact_statement":"trust us"}`, l[0], l[1], l[2])
	}
	b.WriteString(`,{"vulnerability":{"name":"CVE-2026-0009"},"products":[{"@id":"pkg:golang/x"}],"status":"affected"}]}`)
	return []byte(b.String())
}

func check(t *testing.T, body []byte, in Input) []Finding {
	t.Helper()
	sts, others, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if others != 1 {
		t.Fatalf("%d statements of another status, want 1", others)
	}
	in.Asset = asset.String()
	return Check(sts, in)
}

// Each kind of statement meets the evidence that can refute it, or that
// supports it, or is said to be uncheckable, with the reason.
func TestEachStatementIsHeldToTheEvidence(t *testing.T) {
	in := Input{HasBill: true,
		Advisories: []vuln.Advisory{
			advisory("GHSA-aaaa", "CVE-2026-0001", "Go", "github.com/x/lib"),
			advisory("GHSA-bbbb", "CVE-2026-0002", "Go", "github.com/x/old"),
			advisory("DSA-1", "CVE-2026-0003", "Debian", "debian/openssl"),
		},
		Inventory: []vuln.Component{
			component("Go", "github.com/x/lib", "1.2.0"),   // affected
			component("Go", "github.com/x/old", "1.4.0"),   // past the fix
			component("Debian", "debian/openssl", "1.1.0"), // affected by version
		},
		Reach: []vuln.Reach{{Advisory: "GHSA-aaaa", Component: "go:github.com/x/lib",
			Where: asset.String(), Referenced: true}},
	}
	cases := []struct {
		line    [3]string
		outcome Outcome
		reason  Reason
	}{
		{[3]string{"CVE-2026-0001", "pkg:golang/github.com/x/lib@1.2.0", "component_not_present"}, Contradicted, ComponentPresent},
		{[3]string{"CVE-2026-0001", "pkg:golang/github.com/x/lib", "vulnerable_code_not_present"}, Contradicted, VulnerableVersion},
		{[3]string{"CVE-2026-0001", "pkg:golang/github.com/x/lib", "vulnerable_code_not_in_execute_path"}, Contradicted, SymbolReferenced},
		{[3]string{"CVE-2026-0001", "pkg:golang/github.com/x/lib", "inline_mitigations_already_exist"}, Uncheckable, NotCheckableHere},
		{[3]string{"GHSA-bbbb", "pkg:golang/github.com/x/old", "component_not_present"}, Supported, VersionOutside},
		{[3]string{"CVE-2026-0001", "pkg:golang/github.com/x/elsewhere", "component_not_present"}, Uncheckable, ComponentAbsent},
		{[3]string{"CVE-2026-0003", "pkg:deb/debian/openssl@1.1.0", "vulnerable_code_not_present"}, Uncheckable, Backported},
		{[3]string{"CVE-2099-9999", "pkg:golang/github.com/x/lib", "component_not_present"}, Uncheckable, NoAdvisory},
	}
	for _, c := range cases {
		got := check(t, doc(c.line), in)
		if len(got) != 1 || got[0].Outcome != c.outcome || got[0].Reason != c.reason {
			t.Errorf("%v: got %+v, want %s %s", c.line, got, c.outcome, c.reason)
		}
	}
}

// "Not in the execute path" is never supported by a symbol's absence from
// this source: dependencies were not read.
func TestASymbolNotNamedHereSupportsNothing(t *testing.T) {
	in := Input{HasBill: true,
		Advisories: []vuln.Advisory{advisory("GHSA-aaaa", "CVE-2026-0001", "Go", "github.com/x/lib")},
		Inventory:  []vuln.Component{component("Go", "github.com/x/lib", "1.2.0")},
		Reach: []vuln.Reach{{Advisory: "GHSA-aaaa", Component: "go:github.com/x/lib",
			Where: asset.String(), Referenced: false}}}
	got := check(t, doc([3]string{"CVE-2026-0001", "pkg:golang/github.com/x/lib", "vulnerable_code_not_in_execute_path"}), in)
	if got[0].Outcome != Uncheckable || got[0].Reason != OnlyNotReferenced {
		t.Errorf("got %+v", got)
	}
	in.Reach = nil
	got = check(t, doc([3]string{"CVE-2026-0001", "pkg:golang/github.com/x/lib", "vulnerable_code_not_in_execute_path"}), in)
	if got[0].Reason != NotAnalysed {
		t.Errorf("with no analysis: %+v", got)
	}
}

// The vendor's product is not one of the packages a statement is about
// when it names subcomponents: an image missing from the bill supports
// nothing about what is inside it.
func TestTheProductIsNotAPackageWhenItNamesSubcomponents(t *testing.T) {
	sts, _, err := Parse(doc([3]string{"CVE-2026-0001", "pkg:golang/github.com/x/lib", "component_not_present"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(sts) != 1 || strings.Join(sts[0].Packages, ",") != "go:github.com/x/lib" {
		t.Errorf("packages %v", sts[0].Packages)
	}
}

// An asset with no bill of materials can support no statement: absence from
// a bill nobody imported is not absence.
func TestNoBillSupportsNothing(t *testing.T) {
	in := Input{Advisories: []vuln.Advisory{advisory("GHSA-aaaa", "CVE-2026-0001", "Go", "github.com/x/lib")}}
	got := check(t, doc([3]string{"CVE-2026-0001", "pkg:golang/github.com/x/lib", "component_not_present"}), in)
	if got[0].Outcome != Uncheckable || got[0].Reason != NoBill {
		t.Errorf("got %+v", got)
	}
}

// A document that is not one is refused, and one that is huge is bounded.
func TestADocumentIsBounded(t *testing.T) {
	for _, bad := range [][]byte{[]byte("not json"), []byte(`{"statements":[]}`),
		make([]byte, MaxDocument+1)} {
		if _, _, err := Parse(bad); err == nil {
			t.Errorf("%.20q was read", bad)
		}
	}
}
