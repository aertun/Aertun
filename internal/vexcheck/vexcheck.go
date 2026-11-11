// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package vexcheck holds a "not affected" claim against what this program
// knows about the asset it is about.
//
// # Why
//
// Vendors, scanners and AI triage tools now answer vulnerability alerts with
// VEX statements — "not affected: the vulnerable code is not in the execute
// path" — and a statement like that closes the alert wherever it is read.
// Nobody checks it, because checking needs the asset's own bill of
// materials, the advisory's affected ranges and its symbols, and the asset's
// source, and the party writing the statement has the first at most. This
// program has all four (internal/vuln, internal/reach). So each statement is
// held against them, and called contradicted, supported or uncheckable,
// with the reason in a closed word.
//
// # What it will and will not say
//
// It refutes on evidence and proves only on evidence that could have
// refuted. A component the bill lists at a version the advisory names
// contradicts "the component is not present"; the same version contradicts
// "the vulnerable code is not present", except in a Linux distribution's
// packages, which backport a fix without changing the version, so there it
// is uncheckable. "Not in the execute path" is contradicted when this
// asset's own source names the vulnerable symbol, and never supported by the
// symbol's absence, because dependencies were not read (internal/reach). A
// version outside every affected range supports any "not affected".
//
// A bill that does not list the component supports nothing. Package names
// are spelt differently by a bill, a package URL and an advisory database —
// a distribution's namespace in one and not another — so a component that
// is missing may only be misspelt, and absence that could be a spelling
// would make any statement look supported. Everything else is uncheckable,
// and said so.
//
// Nothing the statement's author wrote — its impact statement, its author's
// name, its notes — is read past the fields matched on.
package vexcheck

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/sca"
	"github.com/aertun/aertun/internal/vuln"
)

// MaxDocument bounds a VEX document read.
const MaxDocument = 16 << 20

// MaxStatements bounds the statements one document may make.
const MaxStatements = 50_000

// A document as OpenVEX writes it, read for the fields matched on and
// nothing else. Unknown fields are ignored rather than refused: the format
// carries more than this reads, and refusing a conforming document for
// fields it is allowed to have would refuse every real one.
type document struct {
	Statements []struct {
		Vulnerability struct {
			Name    string   `json:"name"`
			ID      string   `json:"@id"`
			Aliases []string `json:"aliases"`
		} `json:"vulnerability"`
		Products []struct {
			ID            string `json:"@id"`
			Subcomponents []struct {
				ID string `json:"@id"`
			} `json:"subcomponents"`
		} `json:"products"`
		Status        string `json:"status"`
		Justification string `json:"justification"`
	} `json:"statements"`
}

// Statement is one not_affected statement, as matched: the vulnerability's
// names, the packages it is about, and the justification.
type Statement struct {
	Names         []string
	Packages      []string
	Justification vuln.Justification
}

// Parse reads a document's not_affected statements, and how many statements
// it made with another status.
func Parse(body []byte) ([]Statement, int, error) {
	if len(body) > MaxDocument {
		return nil, 0, fmt.Errorf("the document is larger than the %d bytes one check reads", MaxDocument)
	}
	var d document
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, 0, fmt.Errorf("the document is not OpenVEX JSON")
	}
	if len(d.Statements) == 0 {
		return nil, 0, fmt.Errorf("the document makes no statements")
	}
	if len(d.Statements) > MaxStatements {
		return nil, 0, fmt.Errorf("the document makes more than the %d statements one check reads", MaxStatements)
	}
	var out []Statement
	others := 0
	for _, s := range d.Statements {
		if s.Status != string(vuln.NotAffected) {
			others++
			continue
		}
		st := Statement{Justification: vuln.Justification(s.Justification)}
		for _, n := range append([]string{s.Vulnerability.Name, s.Vulnerability.ID}, s.Vulnerability.Aliases...) {
			if n = strings.TrimSpace(n); n != "" {
				st.Names = append(st.Names, n)
			}
		}
		seen := map[string]bool{}
		for _, p := range s.Products {
			// The product is the vendor's thing — an image, an application
			// — and the subcomponents are the packages in it the statement
			// is about. The product stands for the package only when it
			// names none.
			ids := []string{p.ID}
			if len(p.Subcomponents) > 0 {
				ids = ids[:0]
			}
			for _, sub := range p.Subcomponents {
				ids = append(ids, sub.ID)
			}
			for _, id := range ids {
				if eco, name, ok := sca.ParsePURL(id); ok {
					k := vuln.Key(eco, name)
					if !seen[k] {
						seen[k] = true
						st.Packages = append(st.Packages, k)
					}
				}
			}
		}
		out = append(out, st)
	}
	return out, others, nil
}

// Outcome is what one statement came to.
type Outcome string

const (
	Supported    Outcome = "supported"
	Contradicted Outcome = "contradicted"
	Uncheckable  Outcome = "uncheckable"
)

// Reason is why, in a closed set of words.
type Reason string

// The reasons are the closed set a not-affected proof names
// (internal/proof), so a reason given here is one a proof may carry.
const (
	// Contradicted.
	ComponentPresent  Reason = proof.VEXComponentPresent
	VulnerableVersion Reason = proof.VEXVulnerableVersion
	SymbolReferenced  Reason = proof.VEXSymbolReferenced
	// Supported.
	VersionOutside Reason = proof.VEXVersionOutside
	// Uncheckable.
	ComponentAbsent   Reason = proof.VEXNotInTheBill
	NoAdvisory        Reason = proof.VEXNoAdvisory
	NoPackage         Reason = proof.VEXNoPackage
	NoBill            Reason = proof.VEXNoBill
	VersionUndecided  Reason = proof.VEXVersionUndecided
	Backported        Reason = proof.VEXBackported
	NotAnalysed       Reason = proof.VEXNotAnalysed
	OnlyNotReferenced Reason = proof.VEXNotNamedDirectly
	NotCheckableHere  Reason = proof.VEXNotCheckable
)

// Reasons lists every reason, in the order a reader meets them.
func Reasons() []Reason {
	var out []Reason
	for _, r := range proof.VEXReasons() {
		out = append(out, Reason(r))
	}
	return out
}

// Finding is one statement about one package, checked.
type Finding struct {
	Advisory  string
	Component string
	Outcome   Outcome
	Reason    Reason
}

// Input is what the statements are held against, for one asset.
type Input struct {
	Asset      string
	Advisories []vuln.Advisory
	// Inventory are the components the asset's bill lists; HasBill says it
	// has one at all.
	Inventory []vuln.Component
	HasBill   bool
	Reach     []vuln.Reach
}

// distributions are the ecosystems whose packages backport fixes without
// changing the version a vulnerability database ranges over.
var distributions = map[string]bool{"debian": true, "ubuntu": true, "red hat": true,
	"alpine": true, "rocky linux": true, "almalinux": true, "suse": true, "opensuse": true}

func ecosystemOf(key string) string {
	eco, _, _ := strings.Cut(key, ":")
	return eco
}

// Check holds each statement against the input.
func Check(statements []Statement, in Input) []Finding {
	byName := map[string]*vuln.Advisory{}
	for i := range in.Advisories {
		a := &in.Advisories[i]
		for _, n := range append([]string{a.ID}, a.Aliases...) {
			byName[strings.ToUpper(n)] = a
		}
	}
	installed := map[string][]vuln.Component{}
	for _, c := range in.Inventory {
		if c.Where.String() == in.Asset {
			installed[c.Key()] = append(installed[c.Key()], c)
		}
	}
	reachOf := map[string]vuln.Reach{}
	for _, r := range in.Reach {
		if r.Where == in.Asset {
			reachOf[r.Advisory+"\x00"+r.Component] = r
		}
	}
	var out []Finding
	for _, st := range statements {
		var adv *vuln.Advisory
		for _, n := range st.Names {
			if a := byName[strings.ToUpper(n)]; a != nil {
				adv = a
				break
			}
		}
		if adv == nil {
			out = append(out, Finding{Outcome: Uncheckable, Reason: NoAdvisory})
			continue
		}
		if len(st.Packages) == 0 {
			out = append(out, Finding{Advisory: adv.ID, Outcome: Uncheckable, Reason: NoPackage})
			continue
		}
		for _, pkg := range st.Packages {
			out = append(out, checkOne(adv, pkg, st.Justification, installed[pkg], in, reachOf))
		}
	}
	return out
}

func checkOne(adv *vuln.Advisory, pkg string, j vuln.Justification, comps []vuln.Component,
	in Input, reachOf map[string]vuln.Reach) Finding {

	f := Finding{Advisory: adv.ID, Component: pkg}
	switch {
	case !in.HasBill:
		f.Outcome, f.Reason = Uncheckable, NoBill
		return f
	case len(comps) == 0:
		f.Outcome, f.Reason = Uncheckable, ComponentAbsent
		return f
	}
	worst := vuln.Outside
	for _, c := range comps {
		v, _ := adv.Applies(c)
		switch {
		case v == vuln.Vulnerable:
			worst = vuln.Vulnerable
		case v == vuln.Undecided && worst != vuln.Vulnerable:
			worst = vuln.Undecided
		}
	}
	switch worst {
	case vuln.Outside, vuln.Patched:
		f.Outcome, f.Reason = Supported, VersionOutside
		return f
	case vuln.Undecided:
		f.Outcome, f.Reason = Uncheckable, VersionUndecided
		return f
	}
	// Installed at a version the advisory names.
	switch j {
	case vuln.ComponentNotPresent:
		f.Outcome, f.Reason = Contradicted, ComponentPresent
	case vuln.VulnerableCodeNotPresent:
		if distributions[ecosystemOf(pkg)] {
			f.Outcome, f.Reason = Uncheckable, Backported
		} else {
			f.Outcome, f.Reason = Contradicted, VulnerableVersion
		}
	case vuln.VulnerableCodeNotInExecutePath:
		r, ok := reachOf[adv.ID+"\x00"+pkg]
		switch {
		case !ok:
			f.Outcome, f.Reason = Uncheckable, NotAnalysed
		case r.Referenced:
			f.Outcome, f.Reason = Contradicted, SymbolReferenced
		default:
			f.Outcome, f.Reason = Uncheckable, OnlyNotReferenced
		}
	default:
		f.Outcome, f.Reason = Uncheckable, NotCheckableHere
	}
	return f
}
