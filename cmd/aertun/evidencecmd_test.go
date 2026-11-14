// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/evidence"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
	"github.com/aertun/aertun/internal/telemetry"
)

var (
	evSince = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	evUntil = time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
)

func evEvent(at time.Time, raw map[string]string, ips ...string) telemetry.Event {
	e := telemetry.Event{Time: at, Received: at, Source: "okta/system", Class: telemetry.ClassAuthentication,
		Actor: telemetry.ID{Issuer: "okta", Value: "dana@example.com"}, Raw: raw}
	for _, ip := range ips {
		e.Observables = append(e.Observables, telemetry.Observable{Kind: telemetry.ObservableIP, Value: ip})
	}
	return e
}

// evidenceSite is a store whose events arrived from an hour before the
// period to an hour after it: one alert, ALERT-7731, failing sign-ins from
// 203.0.113.9, and three failures in all.
func evidenceSite(t *testing.T) string {
	t.Helper()
	root := reconcileSite(t)
	evidenceNow = func() time.Time { return evUntil.Add(48 * time.Hour) }
	t.Cleanup(func() { evidenceNow = time.Now })
	appendAgentEvents(t, root,
		evEvent(evSince.Add(-time.Hour), map[string]string{"outcome": "SUCCESS"}),
		evEvent(evSince.Add(24*time.Hour), map[string]string{"alert": "ALERT-7731", "outcome": "FAILURE"},
			"203.0.113.9"),
		evEvent(evSince.Add(48*time.Hour), map[string]string{"outcome": "FAILURE"}),
		evEvent(evSince.Add(72*time.Hour), map[string]string{"outcome": "FAILURE", "client": "198.51.100.7"}),
		evEvent(evUntil.Add(time.Hour), map[string]string{"outcome": "SUCCESS"}))
	return root
}

// evReport is a report over the site's period with claims.
func evReport(since, until time.Time, claims ...string) string {
	return `{"format":"aertun/evidence-report/v1","source":"acme-ai","title":"Weekly review",` +
		`"summary":"What the analyst found","since":"` + since.Format(time.RFC3339) + `","until":"` +
		until.Format(time.RFC3339) + `","claims":[` + strings.Join(claims, ",") + `]}`
}

var holding = []string{
	`{"id":"c1","kind":"event-exists","event":"ALERT-7731","class":3002,"event_source":"okta/system",` +
		`"actor":"dana@example.com","statement":"the alert fired"}`,
	`{"id":"c2","kind":"seen","observable":{"type":"ipv4","value":"203.0.113.9"}}`,
	`{"id":"c3","kind":"not-seen","observable":{"type":"domain","value":"evil.example"}}`,
	`{"id":"c4","kind":"count","compare":"exactly","n":3,` +
		`"where":[{"field":"raw.outcome","op":"equals","value":"FAILURE"}]}`,
}

// proveEvidence runs the command on body and opens the proof it wrote.
func proveEvidence(t *testing.T, root, body string, args ...string) (*proof.Statement, string, string, error) {
	t.Helper()
	dir := t.TempDir()
	key, pub := signingFiles(t)
	in, at := filepath.Join(dir, "report"), filepath.Join(dir, "proof.json")
	if err := os.WriteFile(in, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	err := cmdProof(root, append([]string{"evidence", "--report", in, "--key", key, "--public-key", pub,
		"--out", at}, args...))
	if _, serr := os.Stat(at); serr != nil {
		t.Fatalf("no proof was written: %v", err)
	}
	return readStatement(t, at, pub), at, pub, err
}

func outcomesByID(st *proof.Statement) map[string]proof.CitationOutcome {
	out := map[string]proof.CitationOutcome{}
	for _, o := range st.Predicate.Citations.Outcomes {
		out[o.ID] = o
	}
	return out
}

// An investigation whose every citation holds is proven: the alert it names
// happened as it says, the address was seen, the domain was not, and the
// count is exact. The proof is kept, read on every face by the proving
// ground's operations, and verifies offline.
func TestAnInvestigationWhoseCitationsHoldIsProven(t *testing.T) {
	root := evidenceSite(t)
	st, at, pub, err := proveEvidence(t, root, evReport(evSince, evUntil, holding...))
	ev := st.Predicate.Citations
	if err != nil || st.Predicate.Verdict != proof.Proven || ev.Supported != 4 || !ev.Covered ||
		ev.EventsRead != 3 {
		t.Fatalf("%v: %s %+v", err, st.Predicate.Verdict, ev)
	}
	if c4 := outcomesByID(st)["c4"]; c4.Observed != 3 || c4.Stated != 3 || c4.Compare != proof.CountExactly {
		t.Errorf("the count was not checked exactly: %+v", c4)
	}
	if err := proofVerify([]string{"--key", pub, at}); err != nil {
		t.Errorf("proof verify: %v", err)
	}
	kept, _ := proofstore.List(root)
	if len(kept) != 1 || kept[0].Statement == nil || kept[0].Statement.Predicate.Citations == nil {
		t.Fatalf("the proof was not kept: %+v", kept)
	}
	a, err := provingRegistry(root).Invoke("read_proof", cliCaller{root, resolveCaller(root, "")},
		map[string]string{"id": kept[0].ID}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a.Get("kind").Text() != "evidence" || !a.Get("claim").IsOutside() ||
		a.Get("evidence").Get("claims").Text() != "4" {
		t.Errorf("read_proof does not show the evidence proof as one: %s %v %s", a.Get("kind").Text(),
			a.Get("claim").IsOutside(), a.Get("evidence").Get("claims").Text())
	}
	for _, o := range a.Get("evidence").Get("outcomes").Items() {
		if !o.Get("id").IsOutside() || o.Get("outcome").IsOutside() {
			t.Errorf("an outcome is labelled as if its id were this program's or its outcome were not")
		}
	}
}

// A fabricated event id refutes the investigation, by the claim's id and a
// reason from a closed set, as does an address it says was seen and was
// not, and a count that is one off.
func TestWhatTheStoreContradictsRefutes(t *testing.T) {
	root := evidenceSite(t)
	for name, c := range map[string]struct {
		claim, reason string
	}{
		"a fabricated event id": {`{"id":"c9","kind":"event-exists","event":"ALERT-0000"}`, proof.CiteNoSuchEvent},
		"an address never seen": {`{"id":"c9","kind":"seen","observable":{"type":"ipv4","value":"192.0.2.66"}}`,
			proof.CiteNeverSeen},
		"a count one off": {`{"id":"c9","kind":"count","compare":"exactly","n":2,` +
			`"where":[{"field":"raw.outcome","op":"equals","value":"FAILURE"}]}`, proof.CiteCountDiffers},
	} {
		st, _, _, err := proveEvidence(t, root, evReport(evSince, evUntil, append(holding, c.claim)...))
		if err == nil || st.Predicate.Verdict != proof.Refuted {
			t.Errorf("%s: %v %s", name, err, st.Predicate.Verdict)
			continue
		}
		if f := st.Predicate.Checks[2].Failures; len(f) != 1 || f[0] != "claim c9: "+c.reason {
			t.Errorf("%s: the refutation names %v", name, f)
		}
		if o := outcomesByID(st)["c9"]; o.Outcome != proof.CiteContradicted {
			t.Errorf("%s: %+v", name, o)
		}
	}
}

// A report about a period the store does not hold is inconclusive: what it
// cites and the store lacks is uncheckable, never contradicted, and so is
// everything when nothing was ever collected — which reading does not
// create a store for.
func TestAPeriodTheStoreDoesNotHoldIsInconclusive(t *testing.T) {
	root := evidenceSite(t)
	early := evSince.Add(-20 * 24 * time.Hour)
	st, _, _, err := proveEvidence(t, root, evReport(early, early.Add(7*24*time.Hour), holding...))
	ev := st.Predicate.Citations
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || ev.Covered || ev.Contradicted != 0 ||
		ev.Uncheckable != 4 {
		t.Fatalf("%v: %s %+v", err, st.Predicate.Verdict, ev)
	}
	// The alert's source sent nothing in that period, so its claim rests on
	// a source the store does not hold; the rest on a period it does not.
	for id, want := range map[string]string{"c1": proof.CiteSourceNotHeld, "c2": proof.CitePeriodNotHeld,
		"c3": proof.CitePeriodNotHeld, "c4": proof.CitePeriodNotHeld} {
		if o := outcomesByID(st)[id]; o.Reason != want {
			t.Errorf("%s: %s, want %s", id, o.Reason, want)
		}
	}

	empty := reconcileSite(t)
	st, _, _, err = proveEvidence(t, empty, evReport(evSince, evUntil, holding...))
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || st.Predicate.Citations.HeldFrom != "" {
		t.Fatalf("%v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Citations)
	}
	if _, err := os.Stat(spoolDir(empty)); !os.IsNotExist(err) {
		t.Errorf("checking a report created an event store: %v", err)
	}
}

// Plain text yields only the observables and tagged event ids it cites,
// each a claim that it was seen; the rest of the text is not kept.
func TestPlainTextYieldsOnlyWhatItCites(t *testing.T) {
	root := evidenceSite(t)
	text := "Reviewed the week. Sign-ins failed from 203.0.113.9 (alert event:ALERT-7731); the " +
		"client 198.51.100.7 succeeded. Checked report.pdf and config.json, e.g. version 1.2.3.400."
	st, _, _, err := proveEvidence(t, root, text, "--source", "acme-ai", "--since",
		evSince.Format(time.RFC3339), "--until", evUntil.Format(time.RFC3339))
	ev := st.Predicate.Citations
	if err != nil || st.Predicate.Verdict != proof.Proven || ev.Form != proof.FormText || ev.Claims != 3 ||
		ev.Extracted != 3 {
		t.Fatalf("%v: %s %+v", err, st.Predicate.Verdict, ev)
	}
	var cited []string
	for _, o := range ev.Outcomes {
		cited = append(cited, o.Cited)
	}
	if strings.Join(cited, " ") != "203.0.113.9 ALERT-7731 198.51.100.7" {
		t.Errorf("extracted %v", cited)
	}
	key, _ := signingFiles(t)
	in := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(in, []byte(evReport(evSince, evUntil, holding...)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdProof(root, []string{"evidence", "--report", in, "--key", key, "--source", "acme-ai"}); err == nil ||
		!strings.Contains(err.Error(), "for plain text") {
		t.Errorf("a report was taken with a source given beside it: %v", err)
	}
}

// Nothing the report's author wrote reaches the proof, the kept copy, what
// the proving ground answers or the audit log, except ids, observables and
// numbers that passed a strict parser: a marker planted in every free field
// and every parameter that is only compared comes back nowhere.
func TestNothingTheAuthorWroteReachesTheProof(t *testing.T) {
	root := evidenceSite(t)
	// The marker ends in hexadecimal, the shape a parser that kept ids would
	// keep, and in twelve digits of it: a store's log and a proof's envelope
	// are full of digests, where four turn up by chance about once in eighty
	// runs, and twelve are no digest's length.
	const tail = "7f3a9c1e5b2d"
	const marker = "IGNORE-PREVIOUS PLANTED-MARKER " + tail
	planted := strings.NewReplacer(`"Weekly review"`, `"`+marker+`"`,
		`"What the analyst found"`, `"`+marker+`"`, `"the alert fired"`, `"`+marker+`"`,
		`"actor":"dana@example.com"`, `"actor":"`+marker+`"`,
		`"value":"FAILURE"`, `"value":"`+marker+`"`).Replace(evReport(evSince, evUntil,
		append(holding, `{"id":"c5","kind":"count","compare":"at-least","n":0,"statement":"`+marker+`",`+
			`"where":[{"field":"raw.`+marker+`","op":"contains","value":"`+marker+`"}]}`)...))
	if strings.Count(planted, marker) != 8 {
		t.Fatalf("the marker was planted %d times", strings.Count(planted, marker))
	}
	text := "Notes " + marker + " — " + marker + " saw 203.0.113.9."
	for name, c := range map[string]struct {
		body string
		args []string
	}{
		"a report": {planted, nil},
		"plain text": {text, []string{"--source", "acme-ai", "--since", evSince.Format(time.RFC3339),
			"--until", evUntil.Format(time.RFC3339)}},
	} {
		st, at, _, _ := proveEvidence(t, root, c.body, c.args...)
		doc, _ := os.ReadFile(at)
		var env proof.Envelope
		_ = json.Unmarshal(doc, &env)
		payload, _ := base64.StdEncoding.DecodeString(env.Payload)
		statement, _ := json.Marshal(st)
		log, _ := os.ReadFile(auditPath(root))
		kept, _ := proofstore.List(root)
		var answers []string
		for _, k := range kept {
			a, err := provingRegistry(root).Invoke("read_proof", cliCaller{root, resolveCaller(root, "")},
				map[string]string{"id": k.ID}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			text, _ := a.Labelled()
			answers = append(answers, text, describe(k.Statement))
		}
		for where, b := range map[string][]byte{"the envelope": doc, "the payload": payload,
			"the statement": statement, "the audit log": log, "the summary": []byte(describe(st)),
			"the answers": []byte(strings.Join(answers, "\n"))} {
			for _, part := range []string{"PLANTED", "IGNORE", tail} {
				if bytes.Contains(b, []byte(part)) {
					t.Errorf("%s: %s carries what the author wrote (%s)", name, where, part)
				}
			}
		}
	}
}

// The format the usage documents is one the command reads.
func TestTheUsageDocumentsAFormatTheCommandReads(t *testing.T) {
	start := strings.Index(evidenceUsage, "\n  {\n")
	end := strings.Index(evidenceUsage, "\n  }\n")
	if start < 0 || end < start {
		t.Fatal("the usage holds no example report")
	}
	r, err := evidence.Parse([]byte(evidenceUsage[start:end+4]), evidence.Text{})
	if err != nil {
		t.Fatalf("the usage's example is not a report: %v", err)
	}
	var kinds []string
	for _, c := range r.Claims {
		kinds = append(kinds, c.Kind)
	}
	if strings.Join(kinds, " ") != strings.Join(proof.CitationKinds(), " ") {
		t.Errorf("the example shows the kinds %v, not every kind", kinds)
	}
	for _, typ := range proof.ObservableTypes() {
		if !strings.Contains(evidenceUsage, typ) {
			t.Errorf("the usage does not name the observable type %s", typ)
		}
	}
}

// The period must have ended, the store's events are read only by somebody
// who may tune, and a report and a key are both needed.
func TestAnEvidenceProofIsRefusedWhatItCannotStandOn(t *testing.T) {
	root := evidenceSite(t)
	dir := t.TempDir()
	key, _ := signingFiles(t)
	in := filepath.Join(dir, "report")
	if err := os.WriteFile(in, []byte(evReport(evSince, evUntil, holding...)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--report", in}, {"--key", key}, {"--report", in, "--key", key, "stray"}} {
		if err := cmdProof(root, append([]string{"evidence"}, args...)); err == nil ||
			!strings.Contains(err.Error(), "takes --report FILE --key FILE") {
			t.Errorf("%v: %v", args, err)
		}
	}
	evidenceNow = func() time.Time { return evUntil.Add(-time.Hour) }
	if err := cmdProof(root, []string{"evidence", "--report", in, "--key", key}); err == nil ||
		!strings.Contains(err.Error(), "has not ended") {
		t.Errorf("a period not yet ended was checked: %v", err)
	}
	evidenceNow = func() time.Time { return evUntil.Add(48 * time.Hour) }

	// An analyst may read proofs, which is all the command's row asks; the
	// command asks for tune itself before it reads the store.
	for _, g := range [][]string{{"grant", "boss", "admin", "--note", "test setup"}, {"grant", "vic", "analyst"}} {
		if err := cmdAuth(root, g); err != nil {
			t.Fatal(err)
		}
	}
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := ts.Issue("t", "vic", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AERTUN_TOKEN", secret)
	at := filepath.Join(dir, "proof.json")
	if err := cmdProof(root, []string{"list"}); err != nil {
		t.Fatalf("an analyst could not list proofs: %v", err)
	}
	if err := cmdProof(root, []string{"evidence", "--report", in, "--key", key, "--out", at}); err == nil {
		t.Error("an analyst had an investigation checked against the store and signed")
	}
	if _, err := os.Stat(at); !os.IsNotExist(err) {
		t.Errorf("a proof was written for an analyst: %v", err)
	}
}
