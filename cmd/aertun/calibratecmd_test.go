// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/decide"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/telemetry"
)

// steady is a model that gives one verdict at one confidence, whatever it
// is shown; conf can be changed between runs.
type steady struct {
	verdict string
	conf    float64
}

func (s *steady) Name() string { return "stub-model" }
func (s *steady) Complete(context.Context, string, string) (string, error) {
	return suggests(s.verdict, s.conf), nil
}

// ruledSite is a store whose register holds benign findings a verified
// person ruled benign, real findings whose only rulings were recorded by a
// service, by a model and by an identity nobody proved, and open findings
// nobody has ruled.
func ruledSite(t *testing.T, m decide.Model, benign, open int) string {
	t.Helper()
	windtunnelOutput(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv(adapterEnv, "")
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().UTC().Add(-2 * time.Hour)
	reg := finding.NewRegister()
	add := func(id string) {
		reg.Record(finding.Finding{ID: id, Kind: finding.FromDetection,
			Source: "auth.privileged-failed", State: finding.Open,
			Entity:   telemetry.ID{Issuer: "okta", Value: id},
			Severity: telemetry.SeverityHigh, Title: "Failed sign-in",
			Evidence: []finding.Evidence{{At: t0, What: "sign-in failed", Tainted: true}}}, t0)
	}
	for i := 0; i < benign; i++ {
		add(fmt.Sprintf("noise-%02d", i))
	}
	for i := 0; i < 3; i++ {
		add(fmt.Sprintf("real-%d", i))
	}
	for i := 0; i < open; i++ {
		add(fmt.Sprintf("open-%d", i))
	}
	if err := finding.Save(findingsPath(root), reg, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < benign; i++ {
		d := finding.Decision{Finding: fmt.Sprintf("noise-%02d", i), At: time.Now().UTC(),
			By: "dana", Kind: audit.KindHuman, To: finding.Benign, Because: "the backup job"}
		if err := recordE(root, d.Record()); err != nil {
			t.Fatal(err)
		}
	}
	// Three rulings that are not labels: a service's, a model's, and one
	// by a person whose identity was never proved. Were any read as a
	// label, it would be a real finding the stub closed.
	service := finding.Decision{Finding: "real-0", At: time.Now().UTC(), By: "ci",
		Kind: audit.KindService, To: finding.Triaged}.Record()
	ai := finding.Decision{Finding: "real-1", At: time.Now().UTC(), By: "agent",
		Kind: audit.KindHuman, To: finding.Triaged}.Record()
	ai.Kind, ai.Model, ai.Verified = audit.KindAI, "some-model", false
	unproved := finding.Decision{Finding: "real-2", At: time.Now().UTC(), By: "$USER",
		Kind: audit.KindHuman, To: finding.Triaged}.Record()
	unproved.Verified = false
	for _, r := range []audit.Record{service, ai, unproved} {
		if err := recordE(root, r); err != nil {
			t.Fatal(err)
		}
	}
	analystSeam = func(string) (decide.Model, string) { return m, "" }
	t.Cleanup(func() { analystSeam = nil })
	return root
}

func signingFiles(t *testing.T) (key, pub string) {
	t.Helper()
	dir := t.TempDir()
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	key, pub = filepath.Join(dir, "signing.key"), filepath.Join(dir, "pub.json")
	if err := pack.SaveKey(key, k, 0o600); err != nil {
		t.Fatal(err)
	}
	return key, pub
}

func readStatement(t *testing.T, path, pub string) *proof.Statement {
	t.Helper()
	env, err := proof.ReadEnvelope(path)
	if err != nil {
		t.Fatal(err)
	}
	k, err := pack.LoadPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	st, err := proof.Open(env, k)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// The certificate is fitted on what verified people ruled and nothing
// else, is signed, verifies with `proof verify`, and leaves a record.
func TestCalibrateFitsOnVerifiedPeoplesVerdictsAndSigns(t *testing.T) {
	m := &steady{verdict: "benign", conf: 0.92}
	root := ruledSite(t, m, 30, 0)
	key, pub := signingFiles(t)
	cert := filepath.Join(t.TempDir(), "calibration.json")
	if err := cmdAnalyst(root, []string{"calibrate", "--key", key, "--public-key", pub,
		"--out", cert, "--epsilon", "0.2", "--delta", "0.2"}); err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	if info, err := os.Stat(cert); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the certificate was not written 0600: %v %v", info, err)
	}
	st := readStatement(t, cert, pub)
	ev := st.Predicate.Calibration
	if st.Predicate.Verdict != proof.Proven || ev.Cases != 30 || ev.Real != 0 ||
		ev.Closures != 30 || ev.FalseClosures != 0 || ev.Threshold != 0.5 ||
		ev.Model != "stub-model" || ev.Channel != proof.ChannelStated {
		t.Fatalf("verdict %s, evidence %+v", st.Predicate.Verdict, ev)
	}
	if !strings.Contains(st.Predicate.Checks[0].Detail, "3 decision(s) recorded by anybody else were left out") {
		t.Errorf("the labels check: %q", st.Predicate.Checks[0].Detail)
	}
	if err := cmdProof([]string{"verify", "--key", pub, cert}); err != nil {
		t.Errorf("proof verify refused the certificate: %v", err)
	}
	found := false
	events, _ := audit.Read(auditPath(root))
	for _, e := range events {
		if e.Action == "analyst.calibrated" {
			found = true
			if e.Detail["verdict"] != "proven" || e.Detail["left_out"] != "3" ||
				e.Detail["threshold"] != "0.50" {
				t.Errorf("the record: %v", e.Detail)
			}
		}
	}
	if !found {
		t.Error("calibrating left no record")
	}
}

// A store whose audit chain does not verify gives no labels at all.
func TestCalibrateRefusesALogThatDoesNotVerify(t *testing.T) {
	root := ruledSite(t, &steady{verdict: "benign", conf: 0.92}, 30, 0)
	key, _ := signingFiles(t)
	path := auditPath(root)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(body), `"to":"benign"`, `"to":"triaged"`, 1)
	if edited == string(body) {
		t.Fatal("the test edited nothing")
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	err = cmdAnalyst(root, []string{"calibrate", "--key", key, "--out",
		filepath.Join(t.TempDir(), "c.json")})
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("an edited log was calibrated on: %v", err)
	}
}

// Triage gates on a certificate's threshold when it fits, and on the
// declared one — saying so — when it does not.
func TestTriageGatesOnTheCertifiedThreshold(t *testing.T) {
	m := &steady{verdict: "benign", conf: 0.92}
	root := ruledSite(t, m, 30, 2)
	key, pub := signingFiles(t)
	cert := filepath.Join(t.TempDir(), "calibration.json")
	if err := cmdAnalyst(root, []string{"calibrate", "--key", key, "--public-key", pub,
		"--out", cert, "--epsilon", "0.2", "--delta", "0.2"}); err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	body, _ := os.ReadFile(cert)
	other, _ := pack.GenerateKey()

	// Under the declared 0.80 and over the certified 0.50.
	m.conf = 0.6
	ctx, now := context.Background(), time.Now().UTC()
	out, _, err := runTriage(ctx, root, human("dana"), 20, true, now, nil)
	if err != nil || len(out) != 2 {
		t.Fatalf("%d looked at, %v", len(out), err)
	}
	for _, o := range out {
		if o.To != "" || abstainWord(o.Abstained) != "not confident enough" {
			t.Errorf("without a certificate: %+v", o)
		}
	}
	refused := &decide.Calibration{Certificate: body, Key: other.PublicKey()}
	out, _, _ = runTriage(ctx, root, human("dana"), 20, true, now, refused)
	for _, o := range out {
		if o.To != "" || o.Certified || o.Certificate != "refused: signatures do not verify" ||
			abstainWord(o.Abstained) != "no certified gate" {
			t.Errorf("with another key's certificate: %+v", o)
		}
	}
	if line := gateLine(out); !strings.Contains(line, "refused: signatures do not verify") {
		t.Errorf("the run says %q", line)
	}

	// For real, through the command, with the certificate that fits.
	if err := cmdAnalyst(root, []string{"triage", "--calibration", cert,
		"--calibration-key", pub}); err != nil {
		t.Fatal(err)
	}
	events, _ := audit.Read(auditPath(root))
	proposals := 0
	for _, e := range events {
		if e.Action != finding.ProposalAction {
			continue
		}
		proposals++
		if e.Detail["to"] != "benign" || e.Detail["gate"] != "certified" ||
			e.Detail["threshold"] != "0.50" {
			t.Errorf("a proposal recorded %v", e.Detail)
		}
		if !strings.Contains(e.Detail["because"], "threshold 0.50 that a signed calibration certificate sets") {
			t.Errorf("the reason does not say a certificate set the gate: %q", e.Detail["because"])
		}
	}
	if proposals != 2 {
		t.Errorf("%d proposals, want one per open finding", proposals)
	}
	if err := cmdAnalyst(root, []string{"triage", "--calibration", cert}); err == nil ||
		!strings.Contains(err.Error(), "go together") {
		t.Errorf("a certificate without a key to check it against: %v", err)
	}
}

// The adapter digest the operator declares is a sha256 or nothing.
func TestTheAdapterIsADigestOrNothing(t *testing.T) {
	t.Setenv(adapterEnv, "lora-v2")
	if _, err := modelAdapter(); err == nil {
		t.Error("an adapter named rather than digested was accepted")
	}
	t.Setenv(adapterEnv, strings.Repeat("AB", 32))
	if a, err := modelAdapter(); err != nil || a != strings.Repeat("ab", 32) {
		t.Errorf("a digest in capitals: %q %v", a, err)
	}
}

// peoplesVerdicts keeps every record that is not a decision, and every
// decision a verified person recorded, and nothing else.
func TestOnlyVerifiedPeoplesDecisionsAreLabels(t *testing.T) {
	evs := []audit.Event{
		{Action: "finding.benign", Kind: audit.KindHuman, Verified: true},
		{Action: "finding.benign", Kind: audit.KindHuman, Verified: false},
		{Action: "finding.triaged", Kind: audit.KindService, Verified: true},
		{Action: "finding.false-positive", Kind: audit.KindAI, Verified: false},
		{Action: finding.ProposalAction, Kind: audit.KindAI},
		{Action: "incident.link", Kind: audit.KindService, Verified: true},
	}
	kept, left := peoplesVerdicts(evs)
	b, _ := json.Marshal(kept)
	if left != 3 || len(kept) != 3 || !strings.Contains(string(b), `"action":"finding.benign","resource":"","source":"","outcome":"","principal":"","kind":"human","verified":true`) {
		t.Errorf("kept %s, left %d", b, left)
	}
}
