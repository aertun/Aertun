// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aertun/aertun/internal/admin"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// Running the detections over what the event store holds.
//
// The piece that was missing between two that existed. Events were stored by
// `spool add` and rules were tested by `detect test`, and nothing ran the one
// over the other: `triage` would, over events piped into it, and then printed
// twenty lines and kept nothing. So a rule could be written, proved and never
// once evaluated against the estate it was written for.
//
// This reads new arrivals since the last run, evaluates every rule, and folds
// matches into the finding register that the queue screen, the CLI and the
// machine interface all read.

// findingsPath is the finding register.
func findingsPath(root string) string { return filepath.Join(root, "findings.json") }

// detectCursor is the name this producer's position is kept under.
const detectCursor = "detect"

// detectRun evaluates the rules over events that arrived since the last run.
func detectRun(root string, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	rulesAt := fs.String("rules", "", "where the rules live")
	since := fs.Duration("since", 0,
		"on a first run, how far back to look (zero means everything held)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActTriage, auth.AreaSecurity); err != nil {
		return err
	}
	if err := noEventsYet(root); err != nil {
		return err
	}
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		return err
	}
	defer sp.Close()
	sum, err := detectPass(root, *rulesAt, *since, caller, sp)
	if err != nil {
		return err
	}
	// What the run raised goes to the automations, as the estate's
	// findings do: a rule about a critical finding must not depend on
	// which part of the program found it.
	automateFindings(root, sum.New)

	if w.JSON(map[string]any{
		"rules": sum.Rules, "events": sum.Events, "matches": sum.Matches,
		"opened": sum.Opened, "findings": sum.Findings, "through": sum.Through,
		"suppressed": sum.Suppressed, "off": sum.Off,
		"correlations": sum.Corr.Rules, "correlated": sum.Corr.Hits,
		"correlation_dropped": sum.Corr.Dropped,
		"indicators":          sum.Indicators, "indicator_hits": sum.IntelHit,
	}) {
		return nil
	}
	w.Human("%s%d rule(s) over %d new event(s): %d match(es), %d new "+
		"finding(s)%s\n", bold, sum.Rules, sum.Events, sum.Matches, sum.Opened, reset)
	if sum.Suppressed > 0 || sum.Off > 0 {
		w.Human("  %s%d match(es) hidden by suppressions; %d rule(s) switched "+
			"off%s\n", dim, sum.Suppressed, sum.Off, reset)
	}
	if sum.Corr.Rules > 0 {
		w.Human("  %s%d correlation(s): %d window(s) met their condition%s\n",
			dim, sum.Corr.Rules, sum.Corr.Hits, reset)
		if sum.Corr.Dropped > 0 {
			w.Human("  %s%d event(s) could not be placed in a group, or were "+
				"past the cap on groups; that correlation has lost cover%s\n",
				yellow, sum.Corr.Dropped, reset)
		}
	}
	if sum.Indicators > 0 {
		w.Human("  %s%d indicator(s): %d event(s) carried one%s\n", dim,
			sum.Indicators, sum.IntelHit, reset)
	}
	if sum.Events == 0 {
		w.Human("  %snothing arrived since the last run%s\n", dim, reset)
	} else {
		w.Human("  %sthe register holds %d finding(s); read them with "+
			"aertun finding list%s\n", dim, sum.Findings, reset)
	}
	return nil
}

// noEventsYet refuses a run against a site with nothing to read: a mistake
// worth saying, not an empty result worth recording. Its own audit log
// counts: since aertun watches itself, a site that has collected nothing from
// outside still has events, and the store is created to hold them.
func noEventsYet(root string) error {
	if _, serr := os.Stat(spoolDir(root)); serr != nil {
		if own, _ := audit.Read(auditPath(root)); len(own) == 0 {
			return fmt.Errorf("no events have been stored in this site yet; " +
				"add some with aertun spool add")
		}
	}
	return nil
}

// detectSummary is what one pass of the rules did.
type detectSummary struct {
	Rules, Events, Matches, Opened, Suppressed, Off int
	Corr                                            correlationRun
	Indicators, IntelHit, Findings                  int
	Through                                         time.Time
	// New are the findings this pass opened, from any of its parts.
	New []finding.Finding
}

// errNoRules is a pass with nothing to ask.
var errNoRules = errors.New("no rules to run")

// earlierWindow is the earlier of two window starts, where a zero window
// means "from the beginning" and is therefore earlier than every date.
func earlierWindow(a, b time.Time) time.Time {
	if a.IsZero() || b.IsZero() {
		return time.Time{}
	}
	if b.Before(a) {
		return b
	}
	return a
}

// detectPass runs the rules over what arrived since the last pass: the
// command's body, and what the server runs the moment events are pushed to
// it or collected on a schedule.
func detectPass(root, rulesAt string, since time.Duration, caller *Caller, sp *spool.Spool) (*detectSummary, error) {
	loaded, err := rulesIn(rulesDir(root, rulesAt))
	if err != nil {
		return nil, err
	}
	rings, err := loadRings(root)
	if err != nil {
		return nil, err
	}
	sups, err := loadDetectSuppressions(root)
	if err != nil {
		return nil, err
	}
	hits, err := loadHits(root)
	if err != nil {
		return nil, err
	}
	var rules []detect.Rule
	off := 0
	for _, r := range loaded {
		if verr := r.Validate(); verr != nil {
			// Refused, not skipped. A run that silently dropped a rule looks
			// clean because nothing was asked.
			return nil, fmt.Errorf("%s cannot be run: %w", r.ID, verr)
		}
		if rings[r.ID].Ring == detect.Off {
			// Switched off on the record, with a reason. Counted, so the
			// run says how many rules it did not ask.
			off++
			continue
		}
		rules = append(rules, r)
	}
	if err := quietRulesAreCounted(rulesDir(root, rulesAt), rules); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("%w in %s (%d switched off), so a "+
			"run would find nothing and report that as a quiet estate",
			errNoRules, rulesDir(root, rulesAt), off)
	}

	path := findingsPath(root)
	unlock, err := finding.Lock(path)
	if err != nil {
		return nil, err
	}
	defer unlock()

	reg, cursors, err := finding.Load(path)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	before := map[string]bool{}
	for _, f := range reg.All(now) {
		before[f.ID] = true
	}
	from := cursors[detectCursor]
	switch {
	case !from.IsZero():
		// Range is [from, to): the event at exactly the cursor was counted
		// last time.
		from = from.Add(time.Nanosecond)
	case since > 0:
		from = now.Add(-since)
	}

	// What this program itself recorded, so the rules about it read it.
	selfEvents, err := storeSelfEvents(root, sp, now)
	if err != nil {
		return nil, err
	}
	// What its models did, the same way: a proposal, a refusal, a tool
	// call an agent made through MCP.
	agentEvents, err := storeAgentEvents(root, sp, now)
	if err != nil {
		return nil, err
	}

	var events, matches, opened, suppressed int
	var through time.Time
	// The rules are run as compiled programs: every pattern and CIDR block
	// prepared once, and the event's field map built once per event for
	// every rule to share — the map is the event's to give, not each
	// rule's to rebuild.
	progs := make([]*detect.Program, len(rules))
	for i, r := range rules {
		p, cerr := r.Compile()
		if cerr != nil {
			return nil, fmt.Errorf("%s cannot be run: %w", r.ID, cerr)
		}
		progs[i] = p
	}
	match := func(e telemetry.Event) []*detect.Program {
		f := e.Fields()
		var hit []*detect.Program
		for _, p := range progs {
			if p.MatchesFields(e.Source, f) {
				hit = append(hit, p)
			}
		}
		return hit
	}
	// What one event does: every rule that matches it, through the
	// suppressions and rings, into the queue.
	consider := func(e telemetry.Event, matched []*detect.Program) {
		events++
		for _, p := range matched {
			matches++
			// Suppressed: counted against the suppression that hid it and
			// not recorded, so what a suppression costs is a number
			// somebody can look at.
			hidden := false
			for _, sup := range sups {
				if sup.Hides(p.ID, e, now) {
					hits[sup.ID]++
					suppressed++
					hidden = true
					break
				}
			}
			if hidden {
				continue
			}
			if p.Quiet {
				// Counted by a correlation, and raising nothing itself.
				continue
			}
			if _, isNew := reg.Record(finding.Finding{
				Kind: finding.FromDetection, Title: p.Title, Source: p.ID,
				Entity: e.Actor, Severity: p.Severity, State: finding.Open,
				Technique: p.Technique,
				Trial:     rings[p.ID].Ring == detect.Trial,
				Evidence: []finding.Evidence{{
					At: e.Time, What: e.Message, Source: e.Source,
					Alert: alertOf(e),
					// Always. Log text is written by whoever can reach the
					// log, including whoever is being detected.
					Tainted: true,
				}},
			}, e.Time); isNew {
				opened++
			}
		}
	}
	// Aertun's own records first, as they are copied: they are read here,
	// once, and never by the pass below, so that their arrival time — now —
	// does not move the cursor outside platforms' events are read by.
	for _, e := range selfEvents {
		consider(e, match(e))
	}
	for _, e := range agentEvents {
		consider(e, match(e))
	}

	// The correlations and the indicators are prepared before the store is
	// read, because each of the three — rules, correlations, indicators —
	// keeps a window of its own and the one scan has to start at the
	// earliest of them. Every consumer then applies its own window per
	// event, which is what three separate scans did by starting in
	// different places; the events each one sees, and the order it sees
	// them in, are the same as they were, and that is the property the
	// watermark logic in internal/correlate and the reproducibility of the
	// whole run stand on.
	corr, err := prepareCorrelations(rulesDir(root, rulesAt), rules, rings,
		sp, cursors, now)
	if err != nil {
		return nil, err
	}
	held, err := loadIndicators(root)
	if err != nil {
		return nil, err
	}
	live := liveIndicators(held, now)
	intelFrom := cursors[intelCursor]
	if !intelFrom.IsZero() {
		// Range is [from, to): the event at exactly the cursor was counted
		// last time.
		intelFrom = intelFrom.Add(time.Nanosecond)
	}
	// The earliest of the three windows, where a zero window means "from
	// the beginning" and is therefore earlier than every date.
	scanFrom := from
	if corr != nil {
		scanFrom = earlierWindow(scanFrom, corr.from)
	}
	if held.Len() > 0 {
		scanFrom = earlierWindow(scanFrom, intelFrom)
	}
	var intelHit, intelOpened int
	var intelThrough time.Time
	err = sp.Range(scanFrom, time.Time{}, func(e telemetry.Event) error {
		inRules := e.Source != SelfSource && e.Source != AgentSource &&
			(from.IsZero() || !e.Received.Before(from))
		inCorr := corr != nil &&
			(corr.from.IsZero() || !e.Received.Before(corr.from))
		inIntel := held.Len() > 0 &&
			(intelFrom.IsZero() || !e.Received.Before(intelFrom))
		if !inRules && !inCorr && !inIntel {
			return nil
		}
		var matched []*detect.Program
		if inRules || inCorr {
			matched = match(e)
		}
		if inRules {
			if e.Received.After(through) {
				through = e.Received
			}
			consider(e, matched)
		}
		if inCorr {
			if oerr := corr.observe(e, matched, sups, now); oerr != nil {
				return oerr
			}
		}
		if inIntel {
			if e.Received.After(intelThrough) {
				intelThrough = e.Received
			}
			for _, h := range live.Match(e) {
				intelHit++
				if _, isNew := reg.Record(intelFinding(h, e), e.Time); isNew {
					intelOpened++
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !through.IsZero() {
		cursors[detectCursor] = through
	}
	if !intelThrough.IsZero() {
		cursors[intelCursor] = intelThrough
	}
	// The correlations decide only now: a window can be closed once every
	// event that could land in it has been observed, and the scan above was
	// the last of those.
	corrRun, err := corr.finish(root, rings, reg, cursors, now)
	if err != nil {
		return nil, err
	}
	opened += corrRun.Opened + intelOpened
	if err := finding.Save(path, reg, cursors); err != nil {
		return nil, err
	}
	if suppressed > 0 {
		if err := saveJSONFile(hitsPath(root), hits); err != nil {
			return nil, err
		}
	}
	record(root, audit.Record{
		Action: "detect.run", Resource: "/findings", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		Detail: map[string]string{
			"rules": strconv.Itoa(len(rules)), "events": strconv.Itoa(events),
			"matches": strconv.Itoa(matches), "opened": strconv.Itoa(opened),
			"suppressed": strconv.Itoa(suppressed), "off": strconv.Itoa(off),
			"correlations":   strconv.Itoa(corrRun.Rules),
			"correlated":     strconv.Itoa(corrRun.Hits),
			"indicators":     strconv.Itoa(held.Len()),
			"indicator_hits": strconv.Itoa(intelHit),
		},
	})
	sum := &detectSummary{Rules: len(rules), Events: events, Matches: matches,
		Opened: opened, Suppressed: suppressed, Off: off, Corr: corrRun,
		Indicators: held.Len(), IntelHit: intelHit, Findings: reg.Len(), Through: through}
	for _, f := range reg.All(now) {
		// Trial findings are recorded but kept from the automations, as Risk
		// keeps them from its scores (risk.go): a rule that has not earned
		// the queue has not earned the power to suspend an account or mail
		// people either. There is no "trial" condition a rule author could
		// let them in by — Kinds lists no such field — so the exclusion is
		// made here, where what the automations see of a run is collected,
		// rather than left to every author to remember.
		if !before[f.ID] && f.State == finding.Open && !f.Trial {
			sum.New = append(sum.New, f)
		}
	}
	return sum, nil
}

// findingsCapability is the finding register for the admin: the same queue
// `aertun finding list` prints, and decisions written the way `aertun finding
// decide` writes them.
func findingsCapability(root string) *admin.Findings {
	return &admin.Findings{
		Queue: func(now time.Time) ([]finding.Finding, bool, error) {
			q, err := loadQueue(root, now)
			return q, fileExists(findingsPath(root)), err
		},
		History: func(id string) ([]finding.Decision, error) {
			events, err := audit.Read(auditPath(root))
			if err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			return finding.History(id, finding.FromAudit(events)), nil
		},
		Proposals: func(id string) ([]finding.Proposal, error) {
			events, err := audit.Read(auditPath(root))
			if err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			return finding.ProposalsFromAudit(events, id), nil
		},
		Decide: func(d finding.Decision) error {
			if err := d.Validate(); err != nil {
				return err
			}
			return recordE(root, d.Record())
		},
	}
}

// alertOf is the id another product gave the alert an event is, when the
// source's mapping named one: checked again for its shape here, because an
// event can reach the store by paths other than a mapping.
func alertOf(e telemetry.Event) string {
	if v := e.Raw[telemetry.AlertField]; telemetry.ValidAlertID(v) {
		return v
	}
	return ""
}
