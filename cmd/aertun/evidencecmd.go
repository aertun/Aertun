// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/evidence"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// `aertun proof evidence --report FILE --key FILE`: an investigation an AI
// wrote — a vendor's AI analyst, an agent, this program's own analyst — with
// every citation in it run again against the event store (internal/evidence),
// and signed as an evidence proof (internal/proof) kept where the proving
// ground shows it. The report decides nothing here: a contradicted claim is
// named by its id and a reason from a closed set, and nothing its author wrote
// beyond ids, observables and numbers reaches the proof, the record or what
// this command prints.

// evidenceNow is the clock a proof is made on: whether the period has ended
// is part of the question, and a test cannot wait for it.
var evidenceNow = time.Now

// evidenceUsage is the command's usage, with the report's format: what an
// AI's investigation must look like to be checked claim by claim.
const evidenceUsage = `usage: aertun proof evidence --report FILE --key FILE [--public-key F] [--out F]
       aertun proof evidence --report TEXT-FILE --source NAME --since DATE --until DATE --key FILE

Every claim an investigation cites is run again against the event store and
signed as an evidence proof: supported, contradicted, or uncheckable when the
store does not hold the period or the source the claim is about. The verdict
is refuted when any claim is contradicted, proven only when every claim is
supported and there are at least 3, and inconclusive otherwise.

The report is JSON, at most 1 MiB, with no field the format does not have:

  {
    "format": "aertun/evidence-report/v1",
    "source": "acme-ai",
    "title": "free text for a person; never read",
    "summary": "free text for a person; never read",
    "since": "2026-11-01T00:00:00Z",
    "until": "2026-11-08T00:00:00Z",
    "claims": [
      {"id": "c1", "kind": "event-exists", "event": "ALERT-7731",
       "class": 3002, "event_source": "okta/system", "actor": "dana@example.com",
       "statement": "free text; never read"},
      {"id": "c2", "kind": "seen",
       "observable": {"type": "ipv4", "value": "203.0.113.9"}},
      {"id": "c3", "kind": "not-seen", "event_source": "okta/system",
       "observable": {"type": "domain", "value": "evil.example"}},
      {"id": "c4", "kind": "count", "compare": "at-least", "n": 5,
       "where": [{"field": "source", "op": "equals", "value": "okta/system"},
                 {"field": "raw.outcome", "op": "equals", "value": "FAILURE"}]}
    ]
  }

  source        who wrote it: 2 to 32 of a-z, 0-9 and -, starting with a letter
  since, until  the period, RFC 3339, at most 31 days, ended before now
  id            1 to 32 of letters, digits, . _ -; unique in the report
  kind          event-exists  an event with this id (the platform's own id
                              the event carries) happened in the period;
                              class, event_source and actor, where given,
                              must be that event's
                seen          the observable was in an event in the period
                not-seen      the observable was in no event in the period
                count         the events in the period matching every
                              comparison number at-least, at-most or exactly n
  observable    type is ipv4, ipv6, domain, sha256, sha1, md5 or email, and
                the value must parse as one, strictly
  event_source  for seen, not-seen and count: only that source's events count
  where         1 to 4 comparisons, as the console's hunt makes them: a field,
                an op (equals, contains, prefix or suffix) and a value

An observable is seen when it is a whole value of one of an event's
observables, of its actor, target or device or of a raw field, or a whole
word inside one of those or the event's message: a domain inside a URL, an
address beside a port, an email address's domain. Only whole words count, so
a longer name is never the shorter one inside it. At most 200 claims.

Plain text — any file not starting with { — is read for the observables it
cites and for event ids tagged event:ID or alert:ID; each becomes a claim,
marked extracted, that it was seen in the period, which --since and --until
give, as --source names who wrote it. A domain in text is taken only under a
common top-level domain, because prose is full of file names; nothing else in
the text is kept.

The proof is written to --out or standard output, kept in the store's proving
ground, and checked anywhere with aertun proof verify FILE --key PUBLIC-KEY.
The command fails unless the verdict is proven.
`

func proofEvidence(root string, args []string) error {
	fs := flag.NewFlagSet("proof evidence", flag.ContinueOnError)
	reportAt := fs.String("report", "", "the investigation: a report in the format above, or plain text")
	source := fs.String("source", "", "plain text only: who wrote it, by a short name you choose")
	sinceAt := fs.String("since", "", "plain text only: the period's start, a date or an RFC 3339 time")
	untilAt := fs.String("until", "", "plain text only: the period's end, not included")
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), evidenceUsage, "\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *reportAt == "" || *keyAt == "" || fs.NArg() != 0 {
		return fmt.Errorf("proof evidence takes --report FILE --key FILE: an unsigned check of " +
			"citations is another citation (aertun proof evidence -h shows the report's format)")
	}
	var text evidence.Text
	text.Source = *source
	for _, d := range []struct {
		at   string
		into *time.Time
	}{{*sinceAt, &text.Since}, {*untilAt, &text.Until}} {
		if d.at == "" {
			continue
		}
		t, err := parseDay(d.at)
		if err != nil {
			return err
		}
		*d.into = t
	}
	caller := resolveCaller(root, flagToken)
	// Tune, like the other proofs signed from the store: a signed account
	// of somebody's investigation in this organisation's name is one
	// somebody acts on.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	body, err := proof.ReadBounded(*reportAt, evidence.MaxReport)
	if err != nil {
		return err
	}
	rep, err := evidence.Parse(body, text)
	if err != nil {
		return err
	}
	now := evidenceNow().UTC()
	if rep.Until.After(now) {
		return fmt.Errorf("the period has not ended: what has not happened yet cannot be checked")
	}

	// The store, read for the period by the events' own time. A store never
	// collected into is not created by reading it: it holds nothing, and every
	// claim that rests on absence is uncheckable.
	var cov evidence.Coverage
	read := func(func(telemetry.Event) error) error { return nil }
	var listing []map[string]any
	if _, err := os.Stat(spoolDir(root)); err == nil {
		sp, err := openSpool(root, spool.Options{})
		if err != nil {
			return err
		}
		defer sp.Close()
		for _, seg := range sp.Segments() {
			if cov.From.IsZero() || seg.First.Before(cov.From) {
				cov.From = seg.First
			}
			if seg.Last.After(cov.Until) {
				cov.Until = seg.Last
			}
			listing = append(listing, map[string]any{"name": seg.Name, "events": seg.Events,
				"bytes": seg.Bytes, "sha256": seg.Digest})
		}
		read = func(fn func(telemetry.Event) error) error { return sp.During(rep.Since, rep.Until, fn) }
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	results, events, err := evidence.Check(rep, cov, read)
	if err != nil {
		return err
	}
	in := proof.CitationsInput{Source: rep.Source, Form: rep.Form, Report: body, Since: rep.Since,
		Until: rep.Until, HeldFrom: cov.From, HeldUntil: cov.Until, EventsRead: events,
		Outcomes: evidence.Outcomes(results), Program: version, Now: now}
	if len(listing) > 0 {
		b, _ := json.Marshal(listing)
		in.Materials = append(in.Materials, proof.Material{Name: "event-store", Digest: proof.SHA256(b),
			Entries: len(listing)})
	}
	st, err := proof.ProveCitations(in)
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
	ev := st.Predicate.Citations
	if err := recordE(root, caller.auditRecord("proof.evidence", "/proofs", audit.Success,
		map[string]string{"source": ev.Source, "form": ev.Form, "verdict": string(st.Predicate.Verdict),
			"claims": fmt.Sprint(ev.Claims), "supported": fmt.Sprint(ev.Supported),
			"contradicted": fmt.Sprint(ev.Contradicted), "uncheckable": fmt.Sprint(ev.Uncheckable),
			"since": ev.Since, "until": ev.Until, "sha256": proof.SHA256(body)["sha256"]})); err != nil {
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

// describeCitations is an evidence proof's numbers as a person reads them.
func describeCitations(v *proof.CitationsEvidence) string {
	held := "the store held no events"
	switch {
	case v.Covered:
		held = "the store held the whole period"
	case v.HeldFrom != "":
		held = "the store held arrivals from " + v.HeldFrom + " to " + v.HeldUntil + ", not the whole period"
	}
	return fmt.Sprintf("  evidence: %d claim(s) from %s's %s, %d supported, %d contradicted, %d uncheckable; "+
		"%d event(s) read; %s", v.Claims, v.Source, v.Form, v.Supported, v.Contradicted, v.Uncheckable,
		v.EventsRead, held)
}
