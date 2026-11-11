// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/vexcheck"
)

// `aertun vuln prove-vex FILE --source NAME --where ASSET`: a VEX document's
// "not affected" statements about one asset — from a vendor, a scanner or an
// AI triage tool — held against this program's bill of materials, advisories
// and reachability analysis for that asset (internal/vexcheck), and signed as
// a not-affected proof (internal/proof). The statements decide nothing here:
// a contradicted one is named, and none closes a finding or becomes an
// assessment.

func vulnProveVEX(root string, args []string) error {
	fs := flag.NewFlagSet("vuln prove-vex", flag.ContinueOnError)
	source := fs.String("source", "", "who wrote the document, by a short name you choose")
	where := fs.String("where", "", "the asset the document is about, as issuer:value, the same "+
		"as its bill was imported under")
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	var file string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		file, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if file == "" || *source == "" || *where == "" || *keyAt == "" {
		return fmt.Errorf("vuln prove-vex takes FILE --source NAME --where ISSUER:VALUE --key FILE")
	}
	asset, err := parseAsset(*where)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	// Tune, like the other proofs signed from the store.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	body, err := proof.ReadBounded(file, vexcheck.MaxDocument)
	if err != nil {
		return err
	}
	statements, others, err := vexcheck.Parse(body)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	v, err := loadVulnView(root, now)
	if err != nil {
		return err
	}
	hasBill := false
	for _, c := range v.Inventory {
		if c.Where == asset {
			hasBill = true
			break
		}
	}
	findings := vexcheck.Check(statements, vexcheck.Input{Asset: asset.String(),
		Advisories: v.Advisories, Inventory: v.Inventory, HasBill: hasBill, Reach: v.Reach})
	in := proof.NotAffectedInput{Source: *source, Asset: asset.String(), Document: body,
		Statements: len(statements) + others, NotAffected: len(statements),
		Reasons: map[string]int{}, Program: version, Now: now}
	for _, f := range findings {
		switch f.Outcome {
		case vexcheck.Contradicted:
			in.Contradictions = append(in.Contradictions, proof.VEXContradiction{
				Advisory: f.Advisory, Component: f.Component, Reason: string(f.Reason)})
		case vexcheck.Supported:
			in.Supported++
			in.Reasons[string(f.Reason)]++
		default:
			in.Uncheckable++
			in.Reasons[string(f.Reason)]++
		}
	}
	for _, m := range []struct{ name, path string }{{"advisories", storedAdvisories(root)},
		{"inventory", storedInventory(root)}, {"reach", reachPath(root)}} {
		if b, err := os.ReadFile(m.path); err == nil {
			in.Materials = append(in.Materials, proof.Material{Name: m.name, Digest: proof.SHA256(b)})
		}
	}
	st, err := proof.ProveNotAffected(in)
	if err != nil {
		return err
	}
	env, err := proof.Seal(st, k)
	if err != nil {
		return err
	}
	doc, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	doc = append(doc, '\n')
	if *pubAt != "" {
		if err := pack.WritePublicKey(*pubAt, k.PublicKey()); err != nil {
			return err
		}
	}
	if pubDoc, err := json.Marshal(k.PublicKey()); err == nil {
		keepMade(root, env, pubDoc, caller.Name)
	}
	ev := st.Predicate.NotAffected
	if err := recordE(root, caller.auditRecord("vuln.vex-proved", "/vuln", audit.Success,
		map[string]string{"source": *source, "asset": asset.String(),
			"verdict": string(st.Predicate.Verdict), "supported": fmt.Sprint(ev.Supported),
			"contradicted": fmt.Sprint(ev.Contradicted), "uncheckable": fmt.Sprint(ev.Uncheckable),
			"sha256": proof.SHA256(body)["sha256"]})); err != nil {
		return err
	}
	if *outAt == "" {
		if _, err := os.Stdout.Write(doc); err != nil {
			return err
		}
	} else {
		if err := atomicfile.Write(*outAt, doc, 0o600); err != nil {
			return err
		}
		if !w.JSON(summary(st)) {
			w.Human("%s\n", describe(st))
		}
	}
	return notProven(st)
}
