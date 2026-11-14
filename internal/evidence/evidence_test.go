// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/telemetry"
)

var (
	t0    = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	t1    = t0.Add(7 * 24 * time.Hour)
	whole = Coverage{From: t0.Add(-time.Hour), Until: t1.Add(time.Hour)}
	part  = Coverage{From: t0.Add(24 * time.Hour), Until: t1.Add(time.Hour)}
)

// marker is planted wherever an author can write text, and must never come
// back in an error.
const marker = "IGNORE-PREVIOUS PLANTED-MARKER 7f3a"

func report(claims ...string) []byte {
	return []byte(`{"format":"aertun/evidence-report/v1","source":"acme-ai","title":"t","summary":"s",` +
		`"since":"2026-11-01T00:00:00Z","until":"2026-11-08T00:00:00Z","claims":[` +
		strings.Join(claims, ",") + `]}`)
}

// A report is read strictly: a field the format does not have, anything
// after it, a claim with a parameter its kind does not take, and every
// value that does not parse is refused, naming the claim by its place and
// never repeating what the author wrote.
func TestAReportIsReadStrictly(t *testing.T) {
	ok := `{"id":"c1","kind":"seen","observable":{"type":"ipv4","value":"203.0.113.9"}}`
	many := make([]string, proof.MaxCitations+1)
	for i := range many {
		many[i] = fmt.Sprintf(`{"id":"c%d","kind":"seen","observable":{"type":"ipv4","value":"203.0.113.9"}}`, i)
	}
	q := func(s string) string { return `"` + s + `"` }
	for name, body := range map[string]string{
		"not JSON":         `{"format":`,
		"an unknown field": strings.Replace(string(report(ok)), `"title"`, `"`+marker+`"`, 1),
		"trailing data":    string(report(ok)) + `{}`,
		"another format":   strings.Replace(string(report(ok)), "evidence-report/v1", "evidence-report/v9", 1),
		"a source as words": strings.Replace(string(report(ok)), `"source":"acme-ai"`,
			`"source":`+q(marker), 1),
		"a period unreadable": strings.Replace(string(report(ok)), `"2026-11-01T00:00:00Z"`, q(marker), 1),
		"a period backwards": strings.Replace(string(report(ok)), `"2026-11-01T00:00:00Z"`,
			`"2026-11-09T00:00:00Z"`, 1),
		"a period too long": strings.Replace(string(report(ok)), `"2026-11-01T00:00:00Z"`,
			`"2026-09-01T00:00:00Z"`, 1),
		"too many claims": string(report(many...)),
		"an id twice":     string(report(ok, ok)),
		"an id as words":  string(report(strings.Replace(ok, `"c1"`, q(marker), 1))),
		"a kind as words": string(report(strings.Replace(ok, `"seen"`, q(marker), 1))),
		"a parameter its kind does not take": string(report(
			`{"id":"c1","kind":"seen","observable":{"type":"ipv4","value":"203.0.113.9"},"n":3}`)),
		"an event source as words": string(report(
			`{"id":"c1","kind":"seen","event_source":` + q(marker) + `,"observable":{"type":"ipv4","value":"203.0.113.9"}}`)),
		"an event id as words": string(report(`{"id":"c1","kind":"event-exists","event":` + q(marker) + `}`)),
		"a class that is not one": string(report(
			`{"id":"c1","kind":"event-exists","event":"A-1","class":3000}`)),
		"an actor too long": string(report(
			`{"id":"c1","kind":"event-exists","event":"A-1","actor":` + q(strings.Repeat("a", MaxValue+1)) + `}`)),
		"no observable": string(report(`{"id":"c1","kind":"not-seen"}`)),
		"an observable that is not one": string(report(
			`{"id":"c1","kind":"seen","observable":{"type":"ipv4","value":` + q(marker) + `}}`)),
		"an observable type as words": string(report(
			`{"id":"c1","kind":"seen","observable":{"type":` + q(marker) + `,"value":"203.0.113.9"}}`)),
		"no comparison": string(report(`{"id":"c1","kind":"count","compare":"at-least","n":1,"where":[]}`)),
		"five comparisons": string(report(`{"id":"c1","kind":"count","compare":"at-least","n":1,"where":[` +
			strings.Repeat(`{"field":"source","op":"equals","value":"x"},`, 4) +
			`{"field":"source","op":"equals","value":"x"}]}`)),
		"an op as words": string(report(`{"id":"c1","kind":"count","compare":"at-least","n":1,` +
			`"where":[{"field":"source","op":` + q(marker) + `,"value":"x"}]}`)),
		"an op the hunt does not make": string(report(`{"id":"c1","kind":"count","compare":"at-least","n":1,` +
			`"where":[{"field":"source","op":"matches","value":".*"}]}`)),
		"a field too long": string(report(`{"id":"c1","kind":"count","compare":"at-least","n":1,` +
			`"where":[{"field":` + q(strings.Repeat("f", 65)) + `,"op":"equals","value":"x"}]}`)),
		"a value too long": string(report(`{"id":"c1","kind":"count","compare":"at-least","n":1,` +
			`"where":[{"field":"source","op":"equals","value":` + q(strings.Repeat("v", MaxValue+1)) + `}]}`)),
		"a value of nothing": string(report(`{"id":"c1","kind":"count","compare":"at-least","n":1,` +
			`"where":[{"field":"source","op":"contains","value":" "}]}`)),
		"a comparison as words": string(report(`{"id":"c1","kind":"count","compare":` + q(marker) + `,"n":1,` +
			`"where":[{"field":"source","op":"equals","value":"x"}]}`)),
		"no number": string(report(`{"id":"c1","kind":"count","compare":"at-least",` +
			`"where":[{"field":"source","op":"equals","value":"x"}]}`)),
		"a number below 0": string(report(`{"id":"c1","kind":"count","compare":"at-least","n":-1,` +
			`"where":[{"field":"source","op":"equals","value":"x"}]}`)),
		"a number past the bound": string(report(`{"id":"c1","kind":"count","compare":"at-least",` +
			`"n":1073741825,"where":[{"field":"source","op":"equals","value":"x"}]}`)),
	} {
		_, err := Parse([]byte(body), Text{})
		if err == nil {
			t.Errorf("%s: read", name)
			continue
		}
		// Refused for the reason that applies, where another rule would
		// refuse it too.
		if want := map[string]string{"a period unreadable": "RFC 3339", "a kind as words": "kind is one of",
			"not JSON": "not one in the format"}[name]; !strings.Contains(err.Error(), want) {
			t.Errorf("%s: refused as %q, not for %q", name, err, want)
		}
		if strings.Contains(err.Error(), "PLANTED") || strings.Contains(err.Error(), "IGNORE") {
			t.Errorf("%s: the error repeats what the author wrote: %v", name, err)
		}
	}
	if _, err := Parse(report(ok), Text{}); err != nil {
		t.Fatalf("a good report: %v", err)
	}
	if _, err := Parse(make([]byte, MaxReport+1), Text{}); err == nil {
		t.Error("a report over the bound was read")
	}
}

// A report states its own author and period, and plain text is given them:
// the two are never mixed.
func TestTextIsGivenWhatAReportStates(t *testing.T) {
	text := []byte("We saw 203.0.113.9 beaconing.")
	meta := Text{Source: "acme-ai", Since: t0, Until: t1}
	if _, err := Parse(report(), meta); err == nil {
		t.Error("a report was read with a source and period given beside it")
	}
	if _, err := Parse(text, Text{Since: t0, Until: t1}); err == nil {
		t.Error("text was read with nobody named as its author")
	}
	if _, err := Parse(text, Text{Source: "acme-ai", Since: t1, Until: t0}); err == nil {
		t.Error("text was read for a period that ends before it starts")
	}
	r, err := Parse(text, meta)
	if err != nil || r.Form != proof.FormText || len(r.Claims) != 1 || !r.Claims[0].Extracted {
		t.Fatalf("%v %+v", err, r)
	}
}

// Plain text yields the observables and tagged event ids it cites, strictly
// parsed, once each and in order; nothing else in it is kept.
func TestTextYieldsOnlyWhatParsesStrictly(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	text := "Summary " + marker + ": the host contacted 203.0.113.9, then evil[.]example and " +
		"203.0.113.9 again; dropped " + sha + " (see report.pdf, e.g. config.json, version 1.2.3.400). " +
		"Mail from Attacker@Phish.Example. Alerts: event:ALERT-7731 and alert:okta:9f2. " +
		"Not ids: event: ALERT-1, 999.1.1.1, 2001:db8::1, " + strings.Repeat("ab", 31) + ", ASP.NET.core"
	claims, err := Extract([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range claims {
		if !c.Extracted || c.ID != fmt.Sprintf("x%d", len(got)+1) {
			t.Errorf("claim %+v is not numbered and marked as extracted", c)
		}
		got = append(got, c.Kind+" "+c.ObsType+" "+c.Obs+c.Event)
	}
	want := []string{"seen ipv4 203.0.113.9", "seen domain evil.example", "seen sha256 " + sha,
		"seen email attacker@phish.example", "event-exists  ALERT-7731", "event-exists  okta:9f2",
		"seen ipv6 2001:db8::1"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("extracted\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	var many strings.Builder
	for i := 0; i <= proof.MaxCitations; i++ {
		fmt.Fprintf(&many, "10.0.%d.%d ", i/250, i%250)
	}
	if _, err := Extract([]byte(many.String())); err == nil {
		t.Error("text citing more than a proof carries was read")
	}
}

func ev(at time.Time, source string, raw map[string]string, obs ...string) telemetry.Event {
	e := telemetry.Event{Time: at, Received: at, Source: source, Class: telemetry.ClassAuthentication,
		Actor: telemetry.ID{Issuer: "okta", Value: "dana@example.com"}, Raw: raw}
	for _, o := range obs {
		e.Observables = append(e.Observables, telemetry.Observable{Kind: telemetry.ObservableIP, Value: o})
	}
	return e
}

func check(t *testing.T, cov Coverage, events []telemetry.Event, claims ...string) []Result {
	t.Helper()
	r, err := Parse(report(claims...), Text{})
	if err != nil {
		t.Fatal(err)
	}
	res, _, err := Check(r, cov, func(fn func(telemetry.Event) error) error {
		for _, e := range events {
			if err := fn(e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Each claim comes to the outcome its evidence allows: finding something
// supports or contradicts it however little the store holds, and not
// finding it says something only when the store holds the whole period and
// the source the claim names.
func TestEachClaimComesToWhatTheStoreAllows(t *testing.T) {
	at := t0.Add(48 * time.Hour)
	events := []telemetry.Event{
		ev(at, "okta/system", map[string]string{"alert": "ALERT-7731", "outcome": "FAILURE"}, "203.0.113.9"),
		ev(at, "okta/system", map[string]string{"outcome": "FAILURE"}),
		ev(at, "okta/system", map[string]string{"outcome": "SUCCESS", "client": "198.51.100.7"}),
		// Outside the period: never counted, whatever the reader hands over.
		ev(t1.Add(time.Hour), "okta/system", map[string]string{"alert": "ALERT-LATE", "outcome": "FAILURE"},
			"192.0.2.1"),
		ev(at, "crowdstrike/detections", map[string]string{"severity": "high"}),
	}
	seen := func(kind, value, from string) string {
		src := ""
		if from != "" {
			src = `"event_source":"` + from + `",`
		}
		return `{"id":"c1","kind":"` + kind + `",` + src + `"observable":{"type":"ipv4","value":"` + value + `"}}`
	}
	event := func(id, extra string) string {
		return `{"id":"c1","kind":"event-exists","event":"` + id + `"` + extra + `}`
	}
	count := func(compare string, n int, from string) string {
		src := ""
		if from != "" {
			src = `"event_source":"` + from + `",`
		}
		return fmt.Sprintf(`{"id":"c1","kind":"count",%s"compare":"%s","n":%d,"where":[`+
			`{"field":"raw.outcome","op":"equals","value":"failure"}]}`, src, compare, n)
	}
	for name, c := range map[string]struct {
		claim           string
		cov             Coverage
		outcome, reason string
		observed        int
	}{
		"an event that happened":             {event("ALERT-7731", `,"class":3002,"event_source":"okta/system","actor":"DANA@example.com"`), whole, proof.CiteSupported, proof.CiteFound, 1},
		"an event of another class":          {event("ALERT-7731", `,"class":4001`), whole, proof.CiteContradicted, proof.CiteAttributesDiffer, 1},
		"an event from elsewhere":            {event("ALERT-7731", `,"event_source":"crowdstrike/detections"`), whole, proof.CiteContradicted, proof.CiteAttributesDiffer, 1},
		"an event of another actor":          {event("ALERT-7731", `,"actor":"mallory"`), whole, proof.CiteContradicted, proof.CiteAttributesDiffer, 1},
		"a fabricated event":                 {event("ALERT-0000", ""), whole, proof.CiteContradicted, proof.CiteNoSuchEvent, 0},
		"an event after the period":          {event("ALERT-LATE", ""), whole, proof.CiteContradicted, proof.CiteNoSuchEvent, 0},
		"an event over a gap":                {event("ALERT-0000", ""), part, proof.CiteUncheckable, proof.CitePeriodNotHeld, 0},
		"an event from no source held":       {event("ALERT-0000", `,"event_source":"aws/cloudtrail"`), whole, proof.CiteUncheckable, proof.CiteSourceNotHeld, 0},
		"an event from a source without ids": {event("ALERT-0000", `,"event_source":"crowdstrike/detections"`), whole, proof.CiteUncheckable, proof.CiteIDsNotHeld, 0},
		"seen and seen":                      {seen("seen", "203.0.113.9", ""), part, proof.CiteSupported, proof.CiteFound, 1},
		"seen in a raw field":                {seen("seen", "198.51.100.7", ""), whole, proof.CiteSupported, proof.CiteFound, 1},
		"seen and never seen":                {seen("seen", "192.0.2.77", ""), whole, proof.CiteContradicted, proof.CiteNeverSeen, 0},
		"seen only after the period":         {seen("seen", "192.0.2.1", ""), whole, proof.CiteContradicted, proof.CiteNeverSeen, 0},
		"seen over a gap":                    {seen("seen", "192.0.2.77", ""), part, proof.CiteUncheckable, proof.CitePeriodNotHeld, 0},
		"seen in another source":             {seen("seen", "203.0.113.9", "crowdstrike/detections"), whole, proof.CiteContradicted, proof.CiteNeverSeen, 0},
		"seen in no source held":             {seen("seen", "192.0.2.77", "aws/cloudtrail"), whole, proof.CiteUncheckable, proof.CiteSourceNotHeld, 0},
		"not seen and seen":                  {seen("not-seen", "203.0.113.9", ""), part, proof.CiteContradicted, proof.CiteWasSeen, 1},
		"not seen and absent":                {seen("not-seen", "192.0.2.77", ""), whole, proof.CiteSupported, proof.CiteAbsent, 0},
		"not seen over a gap":                {seen("not-seen", "192.0.2.77", ""), part, proof.CiteUncheckable, proof.CitePeriodNotHeld, 0},
		"not seen in no source held":         {seen("not-seen", "192.0.2.77", "aws/cloudtrail"), whole, proof.CiteUncheckable, proof.CiteSourceNotHeld, 0},
		"a count exactly":                    {count("exactly", 2, ""), whole, proof.CiteSupported, proof.CiteCountHolds, 2},
		"a count one short":                  {count("exactly", 3, ""), whole, proof.CiteContradicted, proof.CiteCountDiffers, 2},
		"a count short over a gap":           {count("at-least", 3, ""), part, proof.CiteUncheckable, proof.CitePeriodNotHeld, 2},
		"a count over over a gap":            {count("at-most", 1, ""), part, proof.CiteContradicted, proof.CiteCountDiffers, 2},
		"a count in another source":          {count("at-most", 0, "crowdstrike/detections"), whole, proof.CiteSupported, proof.CiteCountHolds, 0},
		"a count in no source held":          {count("at-most", 0, "aws/cloudtrail"), whole, proof.CiteUncheckable, proof.CiteSourceNotHeld, 0},
		"nothing held":                       {seen("not-seen", "192.0.2.77", ""), Coverage{}, proof.CiteUncheckable, proof.CitePeriodNotHeld, 0},
	} {
		res := check(t, c.cov, events, c.claim)
		if len(res) != 1 || res[0].Outcome != c.outcome || res[0].Reason != c.reason || res[0].Observed != c.observed {
			t.Errorf("%s: %s %s, observed %d; want %s %s, observed %d", name, res[0].Outcome, res[0].Reason,
				res[0].Observed, c.outcome, c.reason, c.observed)
		}
	}
	// Every outcome is one a proof may carry.
	if _, err := proof.ProveCitations(proof.CitationsInput{Source: "acme-ai", Form: proof.FormReport,
		Report: []byte("{}"), Since: t0, Until: t1, HeldFrom: whole.From, HeldUntil: whole.Until,
		Outcomes: Outcomes(check(t, whole, events,
			`{"id":"c1","kind":"event-exists","event":"ALERT-7731"}`,
			`{"id":"c2","kind":"not-seen","observable":{"type":"ipv4","value":"203.0.113.9"}}`,
			`{"id":"c3","kind":"count","compare":"exactly","n":2,"where":[{"field":"raw.outcome","op":"equals","value":"FAILURE"}]}`)),
		Program: "test", Now: t1}); err != nil {
		t.Errorf("the outcomes are not ones a proof carries: %v", err)
	}
}

// An observable is seen as a whole word inside a value, not only as a whole
// value: a domain inside a URL, an address beside a port, an IPv6 address in
// brackets, an email address after mailto: and its domain, a digest in a
// path, a name in the message. A report that says so is not refuted for
// how the platform happened to store it — and only whole words count, so a
// longer name is never the shorter one inside it.
func TestAnObservableIsSeenAsAWholeWordInsideAValue(t *testing.T) {
	at := t0.Add(24 * time.Hour)
	digest := strings.Repeat("ab", 32)
	e := ev(at, "proxy/http", map[string]string{
		"url":    "https://evil.example/login?next=/",
		"peer":   "203.0.113.9:443",
		"peer6":  "[2001:db8::1]:8443",
		"sender": "mailto:mallory@phish.example",
		"path":   "/quarantine/" + digest + ".bin",
		"host":   "notbad.example",
		"long":   "bad.example.attacker.example",
	})
	e.Message = "blocked a request to c2.example, twice"
	events := []telemetry.Event{e}
	obs := func(kind, typ, value string) string {
		return `{"id":"c1","kind":"` + kind + `","observable":{"type":"` + typ + `","value":"` + value + `"}}`
	}
	for name, c := range map[string]struct {
		claim           string
		outcome, reason string
	}{
		"a domain in a URL":            {obs("seen", "domain", "evil.example"), proof.CiteSupported, proof.CiteFound},
		"not-seen, in a URL":           {obs("not-seen", "domain", "evil.example"), proof.CiteContradicted, proof.CiteWasSeen},
		"an address beside a port":     {obs("seen", "ipv4", "203.0.113.9"), proof.CiteSupported, proof.CiteFound},
		"an IPv6 address in brackets":  {obs("seen", "ipv6", "2001:db8::1"), proof.CiteSupported, proof.CiteFound},
		"an email after mailto":        {obs("seen", "email", "mallory@phish.example"), proof.CiteSupported, proof.CiteFound},
		"an email's domain":            {obs("seen", "domain", "phish.example"), proof.CiteSupported, proof.CiteFound},
		"a digest in a path":           {obs("seen", "sha256", digest), proof.CiteSupported, proof.CiteFound},
		"a name in the message":        {obs("seen", "domain", "c2.example"), proof.CiteSupported, proof.CiteFound},
		"a shorter name inside longer": {obs("seen", "domain", "bad.example"), proof.CiteContradicted, proof.CiteNeverSeen},
		"a name that only ends alike":  {obs("not-seen", "domain", "bad.example"), proof.CiteSupported, proof.CiteAbsent},
	} {
		res := check(t, whole, events, c.claim)
		if len(res) != 1 || res[0].Outcome != c.outcome || res[0].Reason != c.reason {
			t.Errorf("%s: %s %s; want %s %s", name, res[0].Outcome, res[0].Reason, c.outcome, c.reason)
		}
	}
}
