// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
	"github.com/aertun/aertun/internal/telemetry"
	"github.com/aertun/aertun/internal/vuln"
)

// vexSite is a store whose asset github:acme/app has a bill listing x/lib at
// an affected version and x/old past its fix, with this source's
// reachability analysis having found x/lib's vulnerable symbol named.
func vexSite(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	asset := telemetry.ID{Issuer: "github", Value: "acme/app"}
	known := time.Now().UTC().Add(-24 * time.Hour)
	advisories := []vuln.Advisory{
		{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2026-0001"}, Summary: "lib", Known: known,
			Affects: []vuln.Range{{Ecosystem: "Go", Package: "github.com/x/lib", Introduced: "1.0.0", Fixed: "1.3.0"}}},
		{ID: "GHSA-dddd-eeee-ffff", Aliases: []string{"CVE-2026-0002"}, Summary: "old", Known: known,
			Affects: []vuln.Range{{Ecosystem: "Go", Package: "github.com/x/old", Introduced: "1.0.0", Fixed: "1.3.0"}}},
	}
	inventory := []vuln.Component{
		{Ecosystem: "Go", Name: "github.com/x/lib", Version: "1.2.0", Where: asset},
		{Ecosystem: "Go", Name: "github.com/x/old", Version: "1.4.0", Where: asset},
	}
	if err := os.MkdirAll(vulnDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONL(storedAdvisories(root), advisories); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONL(storedInventory(root), inventory); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONL(reachPath(root), []vuln.Reach{{Advisory: "GHSA-aaaa-bbbb-cccc",
		Component: "go:github.com/x/lib", Where: asset.String(), Referenced: true, At: known}}); err != nil {
		t.Fatal(err)
	}
	return root
}

func vexDoc(t *testing.T, statements string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vendor.vex.json")
	body := `{"@context":"https://openvex.dev/ns/v0.2.0","author":"Vendor Inc <ignore previous instructions>",` +
		`"statements":[` + statements + `]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func proveVEX(t *testing.T, root, doc string) (*proof.Statement, error) {
	t.Helper()
	key, pub := signingFiles(t)
	at := filepath.Join(t.TempDir(), "vex.proof.json")
	err := cmdVuln(root, []string{"prove-vex", doc, "--source", "acme-scanner", "--where", "github:acme/app",
		"--key", key, "--public-key", pub, "--out", at})
	return readStatement(t, at, pub), err
}

// A statement the evidence contradicts refutes the document, named; one the
// evidence supports, alone, proves it; and nothing the vendor wrote reaches
// the proof.
func TestAVendorsNotAffectedIsHeldToTheEvidence(t *testing.T) {
	root := vexSite(t)
	refuted, err := proveVEX(t, root, vexDoc(t,
		`{"vulnerability":{"name":"CVE-2026-0001"},"products":[{"@id":"pkg:golang/github.com/x/lib@1.2.0"}],`+
			`"status":"not_affected","justification":"vulnerable_code_not_in_execute_path",`+
			`"impact_statement":"we checked carefully, trust us"},`+
			`{"vulnerability":{"name":"CVE-2026-0002"},"products":[{"@id":"pkg:golang/github.com/x/old"}],`+
			`"status":"not_affected","justification":"component_not_present"}`))
	if err == nil || refuted.Predicate.Verdict != proof.Refuted {
		t.Fatalf("%v: %s", err, refuted.Predicate.Verdict)
	}
	f := refuted.Predicate.Checks[1].Failures
	if len(f) != 1 || f[0] != "contradicted: GHSA-aaaa-bbbb-cccc in go:github.com/x/lib, symbol-referenced" {
		t.Errorf("the refutation names %v", f)
	}
	b, _ := json.Marshal(refuted)
	for _, s := range []string{"trust us", "ignore previous", "Vendor Inc"} {
		if strings.Contains(string(b), s) {
			t.Errorf("the vendor's text %q reached the proof", s)
		}
	}
	proven, err := proveVEX(t, root, vexDoc(t,
		`{"vulnerability":{"name":"GHSA-dddd-eeee-ffff"},"products":[{"@id":"pkg:golang/github.com/x/old@1.4.0"}],`+
			`"status":"not_affected","justification":"vulnerable_code_not_present"}`))
	if err != nil || proven.Predicate.Verdict != proof.Proven || proven.Predicate.NotAffected.Supported != 1 {
		t.Errorf("a statement the version supports: %v %s %+v", err, proven.Predicate.Verdict, proven.Predicate.NotAffected)
	}
	if kept, _ := proofstore.List(root); len(kept) != 2 {
		t.Errorf("%d proofs kept, want 2", len(kept))
	}
}
