// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/windtunnel"
)

// windtunnelOutput points the program's writer at a buffer, so a test can
// read what a command actually rendered. Restored on cleanup, because w is
// the one writer every command shares.
func windtunnelOutput(t *testing.T) *strings.Builder {
	t.Helper()
	buf := &strings.Builder{}
	old := w
	w = &out.Writer{Out: buf}
	t.Cleanup(func() { w = old })
	return buf
}

// No bare word starts anything: the one subcommand that writes a scratch
// spool and a signed document never starts because a word was typed, and an
// unknown word is told the five that exist.
func TestWindtunnelBareWordAndUnknownSubcommandRefuse(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	err := cmdWindtunnel(root, nil)
	if err == nil || !strings.Contains(err.Error(), "needs list-scenarios") {
		t.Fatalf("a bare windtunnel gave %v; the bare word must name what it "+
			"wants", err)
	}
	err = cmdWindtunnel(root, []string{"detonate"})
	if err == nil || !strings.Contains(err.Error(), "unknown windtunnel command") {
		t.Fatalf("an unknown subcommand gave %v", err)
	}
}

// list-scenarios names the corpus: ids, families, safety classes and the
// twin every scenario ships — the screen an operator reads before choosing
// what to run.
func TestWindtunnelListScenariosNamesTheCorpus(t *testing.T) {
	buf := windtunnelOutput(t)
	if err := cmdWindtunnel(t.TempDir(), []string{"list-scenarios"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"agent.trifecta-mailroom-exfil",
		"agent.mcp-rug-pull",
		"agent.injection-hijack-via-issue",
		"agent.slopsquat-install",
		"agent.recorder-blind-window",
		"agent.cost-bomb-loop",
		"agent.refund-flow-normal", // a twin, named as one
		"synthetic-only",           // the safety class, stated
		windtunnel.CorpusName,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("list-scenarios never says %q; choosing what to run "+
				"needs the names", want)
		}
	}
}

// preflight checks without splicing: it holds over the default stream for a
// scenario that belongs there, demands the --scenario it is meaningless
// without, and refuses an id nothing carries.
func TestWindtunnelPreflightHoldsAndRefusesByName(t *testing.T) {
	buf := windtunnelOutput(t)
	root := t.TempDir()
	if err := cmdWindtunnel(root, []string{"preflight", "--scenario",
		"agent.trifecta-mailroom-exfil"}); err != nil {
		t.Fatalf("the trifecta's preflight over the default stream failed: %v",
			err)
	}
	if !strings.Contains(buf.String(), "every check held") {
		t.Errorf("a held preflight does not say so: %q", buf.String())
	}

	err := cmdWindtunnel(root, []string{"preflight"})
	if err == nil || !strings.Contains(err.Error(), "needs --scenario") {
		t.Fatalf("a preflight with no scenario gave %v", err)
	}
	err = cmdWindtunnel(root, []string{"preflight", "--scenario", "x"})
	if err == nil || !strings.Contains(err.Error(), "no scenario called") {
		t.Fatalf("an unknown scenario id gave %v", err)
	}
}

// A run writes a document that verifies, names what ran, and says it is
// unsigned when no key was supplied — the honest default, because an
// unsigned document makes no claim a signature would back.
func TestWindtunnelRunWritesASealedScorecard(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	doc := filepath.Join(root, "scorecard.json")
	if err := cmdWindtunnel(root, []string{"run", "--out", doc}); err != nil {
		t.Fatalf("a corpus run over the default stream failed: %v", err)
	}
	b, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	var card windtunnel.Scorecard
	if err := json.Unmarshal(b, &card); err != nil {
		t.Fatal(err)
	}
	if err := card.Verify(); err != nil {
		t.Fatalf("the document a run wrote does not verify: %v", err)
	}
	if card.Signature != nil {
		t.Error("a run without --key wrote a signature; the document must " +
			"say unsigned, not dress an unsigned run up")
	}
	if card.Schema != windtunnel.DocSchema || card.Mode != "replay" ||
		card.ScoreMode != "reference" {
		t.Errorf("schema %q mode %q scoring %q; the document names what ran "+
			"before how it went", card.Schema, card.Mode, card.ScoreMode)
	}
	if len(card.Rows) != 6 || card.Aggregate.TwinFires != 0 {
		t.Errorf("%d rows, %d twin fires; the whole corpus ran", len(card.Rows),
			card.Aggregate.TwinFires)
	}
}

// scorecard renders a document a run wrote and refuses one that was edited
// after the fact — the digest is the only thing standing between a rendered
// number and a number somebody typed in.
func TestWindtunnelScorecardRendersAndRefusesAnEdit(t *testing.T) {
	buf := windtunnelOutput(t)
	root := t.TempDir()
	doc := filepath.Join(root, "scorecard.json")
	if err := cmdWindtunnel(root, []string{"run", "--scenario",
		"agent.cost-bomb-loop", "--out", doc}); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := cmdWindtunnel(root, []string{"scorecard", doc}); err != nil {
		t.Fatalf("rendering the document a run wrote failed: %v", err)
	}
	if !strings.Contains(buf.String(), "missed 0 of 1 must-alert") {
		t.Errorf("the render does not state the aggregate: %q", buf.String())
	}

	b, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(b), `"missed": 0`, `"missed": 1`, 1)
	if edited == string(b) {
		t.Fatal("the edit found nothing to change; the test must be written " +
			"against the document as written")
	}
	if err := os.WriteFile(doc, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	err = cmdWindtunnel(root, []string{"scorecard", doc})
	if err == nil || !strings.Contains(err.Error(), "edited since it was written") {
		t.Fatalf("an edited scorecard rendered (%v); every figure quoted from "+
			"a document must be pinned to the file it came from", err)
	}
}

// The signing and verifying path, end to end through the command, offline
// and store-free: a run signs with a key the operator named, publishes the
// public half beside the document, and a verifier holding those two files
// and nothing else — no store, no deployment — verifies both signatures.
// And the forgeries refuse: an unsigned document, an edited one, a foreign
// key, and a verify asked to trust the document's own say-so.
func TestWindtunnelVerifyIsOfflineStoreFreeAndRefusesForgeries(t *testing.T) {
	buf := windtunnelOutput(t)
	// The store root is an empty directory the whole way through, and the
	// test finishes by proving nothing was written into it.
	root := t.TempDir()
	work := t.TempDir()
	keyPath := filepath.Join(work, "scorecard-key.json")
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := pack.SaveKey(keyPath, k, 0o600); err != nil {
		t.Fatal(err)
	}
	// Signing happens only where the environment says it is CI; this test
	// is the CI job's path, so it says so (the refusal has its own test).
	t.Setenv("CI", "true")

	card := filepath.Join(work, "scorecard.json")
	pub := filepath.Join(work, "scorecard-pub.json")
	if err := cmdWindtunnel(root, []string{"run",
		"--scenario", "agent.trifecta-mailroom-exfil",
		"--key", keyPath, "--out", card, "--public-key", pub}); err != nil {
		t.Fatalf("a signed run failed: %v", err)
	}
	if _, err := os.Stat(pub); err != nil {
		t.Fatalf("the public half was not published: %v", err)
	}

	buf.Reset()
	// Flags before the file, the way every flag-then-argument command here
	// reads its command line.
	if err := cmdWindtunnel(root, []string{"verify", "--key", pub, card}); err != nil {
		t.Fatalf("offline verify failed: %v", err)
	}
	if !strings.Contains(buf.String(), "both signatures hold") {
		t.Errorf("verify does not say what it checked: %q", buf.String())
	}

	// No key named: the verifier is told what verification needs.
	err = cmdWindtunnel(root, []string{"verify", card})
	if err == nil || !strings.Contains(err.Error(), "verify needs --key") {
		t.Fatalf("verify without a key gave %v", err)
	}

	// A foreign key refuses: the signature names the key that made it.
	foreign, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	foreignPub := filepath.Join(work, "foreign-pub.json")
	if err := pack.WritePublicKey(foreignPub, foreign.PublicKey()); err != nil {
		t.Fatal(err)
	}
	err = cmdWindtunnel(root, []string{"verify", "--key", foreignPub, card})
	if err == nil || !strings.Contains(err.Error(), "signed by key") {
		t.Fatalf("a foreign public key verified the document (%v)", err)
	}

	// An edited document refuses, digest before signature.
	b, err := os.ReadFile(card)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(b), `"caught-alert"`,
		`"caught-telemetry"`, 1)
	if tampered == string(b) {
		t.Fatal("the edit found nothing to change; the test must be written " +
			"against the document as written")
	}
	tamperedPath := filepath.Join(work, "tampered.json")
	if err := os.WriteFile(tamperedPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	err = cmdWindtunnel(root, []string{"verify", "--key", pub, tamperedPath})
	if err == nil || !strings.Contains(err.Error(), "edited since it was written") {
		t.Fatalf("an edited, signed scorecard verified (%v)", err)
	}

	// An unsigned document refuses with its reason.
	unsigned := filepath.Join(work, "unsigned.json")
	if err := cmdWindtunnel(root, []string{"run", "--scenario",
		"agent.cost-bomb-loop", "--out", unsigned}); err != nil {
		t.Fatal(err)
	}
	err = cmdWindtunnel(root, []string{"verify", "--key", pub, unsigned})
	if err == nil || !strings.Contains(err.Error(), "carries no signature") {
		t.Fatalf("an unsigned document verified (%v)", err)
	}

	// And the store root stayed empty: no subcommand opened a store, which
	// is what makes the whole command CI-runnable.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the wind tunnel wrote %d entr(y/ies) into the store root; "+
			"replay needs no store and must not leave marks in one", len(entries))
	}
}

// The refusals the library makes are the refusals the command surfaces: a
// live endpoint where a stream path belongs, their-alerts named as the
// phase-2 mode it still is, and their-Sigma's own honest refusals about
// the library it was handed.
func TestWindtunnelRunRefusesLiveTargetsAndPhaseTwoScoring(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	err := cmdWindtunnel(root, []string{"run", "--over",
		"https://staging.example.internal:4318"})
	if err == nil || !strings.Contains(err.Error(), "live endpoint") {
		t.Fatalf("a URL as --over gave %v; replay is the safety story, and "+
			"the refusal is in code", err)
	}
	err = cmdWindtunnel(root, []string{"run", "--score", "their-alerts:x.json"})
	if err == nil || !strings.Contains(err.Error(), "phase 2") {
		t.Fatalf("their-alerts gave %v; it must be refused with its phase "+
			"rather than half-run", err)
	}
	// their-Sigma runs now; what it refuses is the empty library, which
	// would otherwise score an empty 100%.
	empty := t.TempDir()
	err = cmdWindtunnel(root, []string{"run", "--sigma", empty})
	if err == nil || !strings.Contains(err.Error(), "holds none") {
		t.Fatalf("an empty Sigma directory gave %v; the honest answer is a "+
			"refusal, not a miss rate over nothing", err)
	}
	// And --public-key without --key is a contradiction, not a courtesy.
	err = cmdWindtunnel(root, []string{"run", "--public-key", "x.json"})
	if err == nil || !strings.Contains(err.Error(), "needs --key") {
		t.Fatalf("publishing the public half of nothing gave %v", err)
	}
}

// theirSigmaDir points a command test at the fixture library the internal
// tests score, without a second copy of the bytes to drift.
func theirSigmaDir(sub string) string {
	return filepath.Join("..", "..", "internal", "windtunnel", "testdata",
		sub)
}

// The --sigma flag, end to end: the organisation's own rules score the
// run, the document names the mode, the library's digest and the import
// accounting — and the honest miss a library of one quiet rule leaves is
// on the sealed document, not waved away.
func TestWindtunnelSigmaFlagScoresTheirRules(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	work := t.TempDir()

	caught := filepath.Join(work, "caught.json")
	if err := cmdWindtunnel(root, []string{"run", "--sigma",
		theirSigmaDir("their-sigma"), "--scenario",
		"agent.trifecta-mailroom-exfil", "--out", caught}); err != nil {
		t.Fatalf("a their-Sigma run refused: %v", err)
	}
	b, err := os.ReadFile(caught)
	if err != nil {
		t.Fatal(err)
	}
	var card windtunnel.Scorecard
	if err := json.Unmarshal(b, &card); err != nil {
		t.Fatal(err)
	}
	if err := card.Verify(); err != nil {
		t.Fatalf("the their-Sigma document does not verify: %v", err)
	}
	if !strings.HasPrefix(card.ScoreMode, "their-sigma:") ||
		card.TheirSigma == nil || card.TheirSigma.Read != 3 ||
		card.TheirSigma.Imported != 2 || len(card.TheirSigma.Refused) != 1 {
		t.Fatalf("score mode %q, report %+v; the document names the mode "+
			"and carries the import accounting", card.ScoreMode,
			card.TheirSigma)
	}
	if len(card.Rows) != 1 || card.Rows[0].Outcome != windtunnel.OutcomeCaughtAlert {
		t.Fatalf("the row is %+v; the egress rule tags T1041 and fires",
			card.Rows)
	}

	// The same library through the mode grammar, not the flag: one
	// grammar, two ways in, and both refuse a second instrument.
	err = cmdWindtunnel(root, []string{"run", "--score",
		"their-sigma:" + theirSigmaDir("their-sigma"), "--sigma",
		theirSigmaDir("their-sigma")})
	if err == nil || !strings.Contains(err.Error(), "name one instrument") {
		t.Fatalf("naming the instrument twice gave %v", err)
	}
}

// The diff as the CI gate it is: a caught-then-missed pair exits with the
// regression named, the same pair the other way round is a fix and stays
// clean, identical documents are clean, and a command that cannot run —
// wrong arguments, a missing file, an edited scorecard, two documents
// that must never be pooled — is the usage code, never the regression
// code. The exit contract is pinned by the error types main branches on.
func TestWindtunnelDiffIsTheCIGate(t *testing.T) {
	buf := windtunnelOutput(t)
	root := t.TempDir()
	work := t.TempDir()

	// The pair, both their-Sigma over libraries that differ only in
	// whether the T1041 rule can fire: same engine, same corpus, same
	// mode — comparable documents, one caught, one honestly missed.
	caught := filepath.Join(work, "caught.json")
	if err := cmdWindtunnel(root, []string{"run", "--sigma",
		theirSigmaDir("their-sigma"), "--scenario",
		"agent.trifecta-mailroom-exfil", "--out", caught}); err != nil {
		t.Fatal(err)
	}
	quietLib := t.TempDir()
	missRule := "title: A rule that tags the technique and never fires\n" +
		"id: their.never-fires\nstatus: test\n" +
		"description: \"Intersects T1041, matches nothing.\"\n" +
		"author: their-soc\ndate: 2026-10-30\nlogsource:\n" +
		"    product: otel\n    service: genai\ndetection:\n" +
		"    selection:\n        tool: dns_tunnel\n" +
		"    condition: selection\nlevel: medium\ntags:\n    - attack.t1041\n"
	if err := os.WriteFile(filepath.Join(quietLib, "never.yml"),
		[]byte(missRule), 0o644); err != nil {
		t.Fatal(err)
	}
	missed := filepath.Join(work, "missed.json")
	if err := cmdWindtunnel(root, []string{"run", "--sigma", quietLib,
		"--scenario", "agent.trifecta-mailroom-exfil", "--out", missed}); err != nil {
		t.Fatal(err)
	}

	// The regression: exit 1 through errRegressed, transition named on
	// the screen before the status line.
	buf.Reset()
	err := cmdWindtunnel(root, []string{"diff", caught, missed})
	var regressed errRegressed
	if err == nil || !errors.As(err, &regressed) {
		t.Fatalf("a caught-then-missed pair gave %v; the gate's regression "+
			"code is main's plain failure exit behind errRegressed", err)
	}
	if !strings.Contains(err.Error(), "1 regression(s)") {
		t.Errorf("the status line does not count the regressions: %v", err)
	}
	screen := buf.String()
	if !strings.Contains(screen, "caught-alert → missed (regression)") ||
		!strings.Contains(screen, "exit 1") {
		t.Errorf("the screen does not name the transition and the gate:\n%s",
			screen)
	}

	// The fix, same pair reversed: clean, exit 0.
	buf.Reset()
	if err := cmdWindtunnel(root, []string{"diff", missed, caught}); err != nil {
		t.Fatalf("a missed-then-caught pair gave %v; a fix is a report, "+
			"not a failure", err)
	}
	if !strings.Contains(buf.String(), "missed → caught-alert (fix)") ||
		!strings.Contains(buf.String(), "exit 0") {
		t.Errorf("the fix is not named with a clean verdict:\n%s", buf.String())
	}

	// Identical documents: CI-clean, and the screen says so.
	buf.Reset()
	if err := cmdWindtunnel(root, []string{"diff", caught, caught}); err != nil {
		t.Fatalf("diffing a document with itself gave %v", err)
	}
	if !strings.Contains(buf.String(), "no scenario transition") ||
		!strings.Contains(buf.String(), "exit 0") {
		t.Errorf("an identical pair is not clean-and-said-so:\n%s",
			buf.String())
	}

	// The usage bucket: everything that stops the command from running
	// is exit 2 through errUsage, never the regression code.
	for _, args := range [][]string{
		{caught},
		{},
		{caught, filepath.Join(work, "no-such-card.json")},
	} {
		err := cmdWindtunnel(root, append([]string{"diff"}, args...))
		var usage errUsage
		if err == nil || !errors.As(err, &usage) {
			t.Errorf("diff %v gave %v; what cannot run is the usage code, "+
				"which is the one the regression never borrows", args, err)
		}
	}

	// An edited scorecard is not runnable: the digest check refuses
	// before any transition is read from it.
	b, err := os.ReadFile(missed)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(b), `"outcome": "missed"`,
		`"outcome": "caught-telemetry"`, 1)
	if tampered == string(b) {
		t.Fatal("the edit found nothing to change; the test must be " +
			"written against the document as written")
	}
	editedPath := filepath.Join(work, "edited.json")
	if err := os.WriteFile(editedPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	err = cmdWindtunnel(root, []string{"diff", caught, editedPath})
	var usage errUsage
	if err == nil || !errors.As(err, &usage) ||
		!strings.Contains(err.Error(), "edited since it was written") {
		t.Fatalf("an edited scorecard diffed (%v); a transition quoted "+
			"from an edited document is one somebody typed in", err)
	}

	// And two documents that must never be pooled: a reference-mode card
	// and a their-Sigma card refuse with the reason.
	reference := filepath.Join(work, "reference.json")
	if err := cmdWindtunnel(root, []string{"run", "--scenario",
		"agent.trifecta-mailroom-exfil", "--out", reference}); err != nil {
		t.Fatal(err)
	}
	err = cmdWindtunnel(root, []string{"diff", reference, caught})
	if err == nil || !errors.As(err, &usage) ||
		!strings.Contains(err.Error(), "never pooled") {
		t.Fatalf("a cross-mode diff ran (%v); the modes measure different "+
			"subjects and a transition between them is a fact about the "+
			"join, not the controls", err)
	}

	// The store root stays empty: the gate opens no store either.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the gate wrote %d entr(y/ies) into the store root", len(entries))
	}
}

// The purple loop through the command: a run that drafts its misses writes
// the ledger a person reads — over the shipped pack, two declared gaps, no
// drafts, both refusal records on disk carrying the sentence the discipline
// is named by. The scorecard beside them still verifies, and the store root
// still stays empty: proposing writes one directory the operator named.
func TestWindtunnelRunDraftsItsGapsIntoALedger(t *testing.T) {
	buf := windtunnelOutput(t)
	root := t.TempDir()
	work := t.TempDir()
	drafts := filepath.Join(work, "purple")
	doc := filepath.Join(work, "scorecard.json")
	if err := cmdWindtunnel(root, []string{"run", "--draft-misses", drafts,
		"--out", doc}); err != nil {
		t.Fatalf("a run with drafting refused: %v", err)
	}
	screen := buf.String()
	// The refusal sentence arrives wrapped for a terminal, so the assertion
	// reads it the way a person does: as words, not as one line.
	flat := strings.Join(strings.Fields(screen), " ")
	if !strings.Contains(screen, "purple loop: 0 draft(s), 2 declared gap(s)") {
		t.Errorf("the screen does not state the loop's ledger: %q", screen)
	}
	if !strings.Contains(flat,
		"a miss the telemetry cannot distinguish is a gap to declare, "+
			"not a rule to force") {
		t.Errorf("the refusal sentence is not on the screen; a gap honestly "+
			"declared is a result and is printed as one: %q", screen)
	}
	entries, err := os.ReadDir(drafts)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"agent.slopsquat-install.refused.json":     true,
		"agent.recorder-blind-window.refused.json": true,
	}
	if len(entries) != len(want) {
		t.Fatalf("%d file(s) in the drafts directory; the shipped pack "+
			"leaves exactly the two declared gaps and nothing to propose",
			len(entries))
	}
	for _, e := range entries {
		if !want[e.Name()] {
			t.Errorf("%s is not a refusal this run owes; the loop wrote a "+
				"file nobody asked for", e.Name())
		}
		var rec windtunnel.DraftRecord
		body, err := os.ReadFile(filepath.Join(drafts, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &rec); err != nil {
			t.Fatalf("%s does not decode as an audit record: %v", e.Name(),
				err)
		}
		if rec.Schema != windtunnel.DraftSchema ||
			rec.Outcome != windtunnel.DraftOutcomeRefused ||
			rec.RuleID != "" {
			t.Errorf("%s is %+v; a declared gap carries the schema, the "+
				"refusal and no rule id", e.Name(), rec)
		}
	}
	b, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	var card windtunnel.Scorecard
	if err := json.Unmarshal(b, &card); err != nil {
		t.Fatal(err)
	}
	if err := card.Verify(); err != nil {
		t.Fatalf("the scorecard a drafting run wrote does not verify: %v",
			err)
	}
	// And the loop wrote nowhere else: the store root is empty, and the
	// work directory holds the ledger and the document and nothing else.
	store, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(store) != 0 {
		t.Fatalf("the wind tunnel wrote %d entr(y/ies) into the store root"+
			"; drafting needs no store either", len(store))
	}
	held, err := os.ReadDir(work)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 2 { // the scorecard file and the purple directory
		t.Fatalf("%d entr(y/ies) beside the scorecard; the loop's whole "+
			"footprint is the directory it was given", len(held))
	}
}

// The drafted half of the ledger screen, pinned where the shipped pack
// cannot reach it (it catches everything it carries a rule for): the counts
// a person reads before promoting, and the sentence that says the promotion
// is theirs, not the loop's.
func TestWindtunnelDraftScreenNamesThePromotionAndTheCounts(t *testing.T) {
	buf := windtunnelOutput(t)
	windtunnelPurpleScreen([]windtunnel.DraftRecord{
		{Scenario: "agent.trifecta-mailroom-exfil",
			Outcome:       windtunnel.DraftOutcomeDrafted,
			RuleID:        "draft.trifecta-mailroom-exfil",
			MatchFixtures: 1, RefuseFixtures: 3,
			CaughtFires: 1, AmbientFires: 0},
		{Scenario: "agent.slopsquat-install",
			Outcome: windtunnel.DraftOutcomeRefused,
			Reason: "agent.slopsquat-install: every event its session " +
				"emitted is identical to its benign twin's on every closed " +
				"field, and a miss the telemetry cannot distinguish is a " +
				"gap to declare, not a rule to force"},
	}, "purple")
	screen := buf.String()
	for _, want := range []string{
		"purple loop: 1 draft(s), 1 declared gap(s)",
		"draft.trifecta-mailroom-exfil",
		"purple/draft.trifecta-mailroom-exfil.json",
		"fixtures 1 matched, 3 refused",
		"ambient 0 on the base stream",
		"promote by copying the proposal into the pack, on the record",
		"the loop deploys nothing",
		"refused agent.slopsquat-install",
	} {
		if !strings.Contains(screen, want) {
			t.Errorf("the ledger screen never says %q: %s", want, screen)
		}
	}
}
