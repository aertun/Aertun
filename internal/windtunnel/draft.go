// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// The purple loop: the closed half of the wind tunnel, where a miss becomes
// a proposal instead of a number.
//
// A run attests what the controls caught and what they did not. The
// scorecard is where a conventional BAS product stops — a heatmap, a miss
// rate, an invoice for more content. This package can go one step further
// and stay honest about it, because the miss is not an abstraction here: the
// run spliced the session's exact events into a scratch spool, replayed the
// reference pack over them, and recorded which expectation went unmet. The
// raw material of a detection — the attack's own telemetry, and the benign
// twin's — is evidence the scorecard can name by digest.
//
// So the loop drafts. From a miss whose events the telemetry carried — a
// content miss, or a session nothing alerted on — it derives a candidate
// rule by deterministic code: the narrowest predicate tree over a closed
// vocabulary of fields that matches the session's separable events and
// refuses every event of its benign twin. The must-match fixtures are the
// scenario's own events; the must-not-match fixtures are the twin's. That is
// exactly the discipline the pack's authors apply by hand to every rule in
// internal/detect/pack — the loop automates it honestly, or refuses.
//
// # What the loop refuses, by name
//
// A miss whose events are identical to the twin's on every closed field is a
// gap to declare, not a rule to force: the slopsquat session's install and
// its twin's differ only in a package name nobody vetted, and the
// recorder-blind session's darkness is an absence no event carries. Forcing
// a rule over either would be a detection quoting free text — the thing the
// suppression discipline refuses elsewhere (internal/detect/tuning.go:
// whoever is being detected can put any word in raw.*), refused here before
// the rule exists. A lateness miss is refused because it is a finding about
// the watermark budget, not about the rules. A draft that fires on the base
// stream above a small threshold is refused with its count, because a rule
// that fires on the estate it watches is noise wearing a detection's name.
//
// # Propose, never deploy
//
// A draft lands as a proposal file in the pack's own rule format plus an
// audit record with the closed details. Promoting it is a human act through
// the ring machinery — the file into the pack, on the record. The loop never
// writes the pack, for the same reason tuning.Propose changes nothing
// itself: a detector that edits its own controls can be talked out of the
// one that would have caught it.

// DraftSchema is the audit record's versioned schema name, in the tradition
// of every schema here: fields change meaning between versions, and a record
// from another schema is refused rather than best-effort loaded.
const DraftSchema = "aertun/purple-draft/v1"

// The two outcomes a miss can meet at the loop's hands.
const (
	// DraftOutcomeDrafted: a proposal rule and its audit record were written.
	DraftOutcomeDrafted = "drafted"
	// DraftOutcomeRefused: the miss is a declared gap; the reason is the
	// record, in the sentence the reader deserves.
	DraftOutcomeRefused = "refused"
)

// MaxDraftAmbient is how many times a draft may fire on the base stream
// alone — the estate's own normal traffic, the stream the attack hid among —
// before the loop refuses it with the count.
//
// Five, the same number the trial ring's own arithmetic uses as the floor
// where noise stops being one thing and becomes a habit
// (internal/detect/tuning.go, where five false verdicts is what suggests a
// demotion). The count is reported on every draft whether it refuses or not,
// because a rule's ambient rate is part of what a person is being asked to
// promote.
const MaxDraftAmbient = 5

// draftVocabulary is the closed set of fields a draft may read, each with
// the one operator the pack itself uses on it: equals for the fields whose
// value the boundary stamps, contains for the label list the tool-label
// table declares.
//
// Closed because a draft that quoted raw free text — a package name, a URL,
// an argument — would be a rule about one attacker's spelling with honest
// work wearing it. Everything in this list has one meaning, chosen by a
// connector or declared at the ingest boundary and never by whoever is being
// detected: the source that produced the event, the operation and tool of
// the tool-call grammar, the labels the tool-label table stamped, the
// disposition the pipeline recorded, the issuer of the actor identity.
// raw.labels is split on its commas and compared one label at a time, the
// way the boundary writes it and the pack's own otel rules read it.
var draftVocabulary = []struct {
	field string
	op    detect.Op
	split bool
}{
	{field: "source", op: detect.Equals},
	{field: "message", op: detect.Equals},
	{field: "raw.operation", op: detect.Equals},
	{field: "raw.tool", op: detect.Equals},
	{field: "raw.labels", op: detect.Contains, split: true},
	{field: "disposition", op: detect.Equals},
	{field: "actor.issuer", op: detect.Equals},
}

// draftFieldNames is the vocabulary as a reader meets it in a sentence.
func draftFieldNames() []string {
	out := make([]string, 0, len(draftVocabulary))
	for _, f := range draftVocabulary {
		out = append(out, f.field)
	}
	return out
}

// DraftOptions is what the loop needs: the one decision an operator makes.
type DraftOptions struct {
	// Dir is where the proposals and their audit records land. Required;
	// created when absent. It is never the pack — the loop proposes, a
	// person promotes, and the two directories being different is the wall
	// between those acts.
	Dir string
}

// SpoolFires is what the drafted rule did over one scratch spool: the label
// ("base", a scenario id, or one marked "(twin)") and how many times it
// fired.
type SpoolFires struct {
	Spool string `json:"spool"`
	Fires int    `json:"fires"`
}

// DraftRecord is the loop's whole verdict on one miss: the closed details a
// person reads before promoting, or the sentence that says why no rule was
// forced. It is written to Dir and returned, and it is deterministic — no
// clock, no path, only what the run's own evidence fixed.
type DraftRecord struct {
	Schema string `json:"schema"`
	// Scenario, its digest, and the twin the fixtures refuse.
	Scenario       string `json:"scenario"`
	ScenarioDigest string `json:"scenario_digest"`
	Twin           string `json:"twin"`
	// Miss is the miss this draft answers, in words: which expectation went
	// unmet, or that nothing alerted on the session at all.
	Miss    string `json:"miss"`
	Outcome string `json:"outcome"`

	// Reason carries the refusal sentence, when the outcome is refused.
	Reason string `json:"reason,omitempty"`

	// The draft, when there is one.
	RuleID     string `json:"rule_id,omitempty"`
	RuleDigest string `json:"rule_digest,omitempty"`
	// MatchFixtures and RefuseFixtures are the fixture counts: the scenario's
	// own events that must fire, the twin's that must not.
	MatchFixtures  int `json:"match_fixtures,omitempty"`
	RefuseFixtures int `json:"refuse_fixtures,omitempty"`
	// Separable is how many of the session's events the telemetry can tell
	// from the twin's; Indistinguishable is how many it cannot — the part of
	// the gap that stays declared.
	Separable         int `json:"separable_events,omitempty"`
	Indistinguishable int `json:"indistinguishable_events,omitempty"`
	// CaughtFires is the draft's fires above ambient on the scenario's own
	// spool; AmbientFires its fires on the base stream alone, reported on
	// every record. Replay is every spool it was run over, counts and all.
	CaughtFires  int          `json:"caught_fires,omitempty"`
	AmbientFires int          `json:"ambient_fires"`
	Replay       []SpoolFires `json:"replay,omitempty"`

	// The digests that pin the record to what it answers.
	PackDigest      string `json:"pack_digest"`
	ScorecardDigest string `json:"scorecard_digest"`
}

// draftable says whether a row is a gap the loop may answer. A content miss
// and a telemetry-only session both are: the events are in the stream the
// stack retains and no detection alerted. A lateness miss is not (a finding
// about the watermark budget), a wrongly-quiet row is not (a precision
// failure, not a detection gap), and a caught row is not a miss at all.
func draftable(row Row) bool {
	switch row.Outcome {
	case OutcomeMissed:
		return row.MissKind() == MissContent
	case OutcomeCaughtTelemetry:
		return true
	}
	return false
}

// Draft walks a scorecard's misses and drafts from each: the run's own
// scratch spools and the corpus it ran, nothing else.
//
// The loop derives everything from artifacts the run left behind, so a draft
// is a function of evidence that still exists — the scorecard's rows and
// seed, the scratch spools it names, the scenario bytes it digested. A
// scorecard whose scratch is gone is refused rather than re-derived, because
// a draft that cannot name its evidence is a rule quoting a memory.
func Draft(card *Scorecard, ref *Reference, opts DraftOptions) ([]DraftRecord, error) {
	if strings.TrimSpace(opts.Dir) == "" {
		return nil, fmt.Errorf("drafting needs a directory for the proposals; " +
			"it is where they land, and it is never the pack")
	}
	if err := card.Verify(); err != nil {
		return nil, fmt.Errorf("the scorecard: %w", err)
	}
	if ref.Digest != card.PackDigest {
		return nil, fmt.Errorf("the reference pack's digest is %s and the "+
			"scorecard ran against %s: the pack has moved since the run, and "+
			"a draft must answer the misses of the run that recorded them — "+
			"rerun, then draft", shortDigest(ref.Digest),
			shortDigest(card.PackDigest))
	}
	// The loose corpus: a scenario whose expectation this instrument lacks is
	// the miss this card already reported, and the honesty rules in the
	// scorer said so. The strict co-test belongs to the shipped pack's own
	// build, not to the loop.
	corpus, err := loadCorpus(ref, false)
	if err != nil {
		return nil, err
	}
	byID := map[string]*Loaded{}
	for _, l := range corpus {
		byID[l.Scenario.ID] = l
	}
	for _, s := range card.Scenarios {
		l := byID[s.ID]
		if l == nil || l.Digest != s.Digest {
			return nil, fmt.Errorf("scenario %s's bytes have changed since "+
				"the run (the scorecard digested %s); a draft's fixtures "+
				"are the session the run spliced, and a session that is no "+
				"longer those bytes is a different one", s.ID,
				shortDigest(s.Digest))
		}
	}

	// The run's own evidence: the base stream as the ambient spool recorded
	// it, the anchor and seed that placed every session. The same inputs
	// place the same bytes — determinism is what lets the loop quote them.
	base, err := readScratchSpool(filepath.Join(card.Scratch, "ambient"))
	if err != nil {
		return nil, fmt.Errorf("the scratch spools the scorecard names are "+
			"gone or unreadable (%w); the loop drafts from the run's own "+
			"evidence, and evidence that no longer exists is a rerun, not a "+
			"draft", err)
	}
	anchor, err := DefaultAnchor(base)
	if err != nil {
		return nil, err
	}

	// Derive once: the same deterministic function feeds the fixtures, the
	// replay and the record, so the three can never disagree.
	derived := map[string]*derivation{}
	for _, row := range card.Rows {
		if !draftable(row) {
			continue
		}
		l := byID[row.Scenario]
		if l == nil {
			continue
		}
		d, err := derive(l.Scenario, base, anchor, card.Seed)
		if err != nil {
			return nil, err
		}
		derived[row.Scenario] = d
	}
	counts, err := replayCounts(card, derived)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}
	var out []DraftRecord
	for _, row := range card.Rows {
		// The lateness refusal: named before anything is derived, because
		// the watermark budget is not a question the tree can answer.
		if row.Outcome == OutcomeMissed && row.MissKind() == MissLateness {
			rec := DraftRecord{Schema: DraftSchema, Scenario: row.Scenario,
				ScenarioDigest: byID[row.Scenario].Digest,
				Twin:           byID[row.Scenario].Scenario.Twin.ID,
				Miss:           missWords(row), Outcome: DraftOutcomeRefused,
				Reason: fmt.Sprintf("%s: the miss was lateness, not content — "+
					"the window closed before the completing event arrived "+
					"under the stream's own watermark, which is a finding "+
					"about the lateness budget. A drafted rule answers a "+
					"content gap, and drafting one here would paper over a "+
					"watermark problem with a detection", row.Scenario),
				PackDigest:      card.PackDigest,
				ScorecardDigest: card.SHA256}
			out = append(out, rec)
			if err := writeDraftRecord(opts.Dir,
				sanitize(row.Scenario)+".refused.json", rec); err != nil {
				return nil, err
			}
			continue
		}
		if !draftable(row) {
			continue
		}
		sc := byID[row.Scenario].Scenario
		d := derived[row.Scenario]
		rec := DraftRecord{Schema: DraftSchema, Scenario: sc.ID,
			ScenarioDigest: byID[row.Scenario].Digest, Twin: sc.Twin.ID,
			Miss: missWords(row), Separable: d.separable,
			Indistinguishable: d.indistinguishable,
			PackDigest:        card.PackDigest, ScorecardDigest: card.SHA256}

		if d.rule == nil {
			rec.Outcome = DraftOutcomeRefused
			rec.Reason = cannotDistinguish(sc)
			out = append(out, rec)
			if err := writeDraftRecord(opts.Dir,
				sanitize(sc.ID)+".refused.json", rec); err != nil {
				return nil, err
			}
			continue
		}

		// The engine's own bar, unforked: the draft must pass Rule.Validate
		// — fixtures that fire and refuse, fields the data carries — and its
		// own fixtures must hold. A derivation that could not pass these is
		// not a draft that was tried and found wanting; it is a bug in the
		// loop, and it comes back as one.
		if err := d.rule.Validate(); err != nil {
			return nil, fmt.Errorf("the loop drafted a rule the engine "+
				"refuses, which is a bug in the loop, not a gap in the pack: "+
				"%w", err)
		}
		for _, res := range d.rule.Test() {
			if !res.OK() {
				return nil, fmt.Errorf("the loop drafted a rule its own "+
					"fixtures refuse, which is a bug in the loop, not a gap "+
					"in the pack: %s", res.Why())
			}
		}
		rec.RuleID = d.rule.ID
		rec.MatchFixtures = d.separable
		rec.RefuseFixtures = countSteps(sc.Twin.Steps)

		// Replay-validate: the counts over every scratch spool the run
		// wrote. The draft must catch the missed session above ambient, stay
		// quiet on every twin, and its ambient rate is reported — and above
		// the threshold, refused with the count.
		c := counts[d.rule.ID]
		rec.Replay = c.replay
		rec.AmbientFires = c.ambient
		rec.CaughtFires = c.scenario[sanitize(row.Scenario)] - c.ambient
		if c.ambient > MaxDraftAmbient {
			rec.Outcome = DraftOutcomeRefused
			rec.Reason = fmt.Sprintf("%s: the drafted rule fired %d time(s) "+
				"on the base stream alone — the estate's own normal traffic "+
				"— and a rule that fires on the estate it watches is noise "+
				"wearing a detection's name. The count is the refusal: the "+
				"gap stays declared until the draft is narrower or the "+
				"labels are honest", sc.ID, c.ambient)
			out = append(out, rec)
			if err := writeDraftRecord(opts.Dir,
				sanitize(sc.ID)+".refused.json", rec); err != nil {
				return nil, err
			}
			continue
		}
		if twinFired, spool, fires := firstTwinFire(c); twinFired {
			rec.Outcome = DraftOutcomeRefused
			rec.Reason = fmt.Sprintf("%s: the drafted rule fired %d time(s) "+
				"above ambient on the benign twin's replay %s, which the "+
				"fixtures said it could not; the derivation and the replay "+
				"disagree, and the draft is refused rather than trusted",
				sc.ID, fires, spool)
			out = append(out, rec)
			if err := writeDraftRecord(opts.Dir,
				sanitize(sc.ID)+".refused.json", rec); err != nil {
				return nil, err
			}
			continue
		}
		if rec.CaughtFires <= 0 {
			return nil, fmt.Errorf("the drafted rule %s did not fire above "+
				"ambient on %s's own spool although its fixtures hold, which "+
				"is a bug in the loop, not a gap in the pack", d.rule.ID,
				sc.ID)
		}

		// The proposal and its audit record. The proposal is the pack's own
		// rule format, byte for byte promotable by copying; the record is
		// the closed details a person reads before promoting.
		body, err := ruleDocument(d.rule)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		rec.RuleDigest = hex.EncodeToString(sum[:])
		rec.Outcome = DraftOutcomeDrafted
		if err := os.WriteFile(filepath.Join(opts.Dir, d.rule.ID+".json"),
			body, 0o600); err != nil {
			return nil, err
		}
		if err := writeDraftRecord(opts.Dir, d.rule.ID+".audit.json",
			rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// missWords is the miss a row records, in words: which must-alert
// expectations went unmet, or that nothing alerted on the session at all —
// the telemetry tier, which is a gap the loop may answer because the events
// are in the stream the stack retains.
func missWords(row Row) string {
	switch row.Outcome {
	case OutcomeCaughtTelemetry:
		return "no detection alerted on the session: its events are in the " +
			"stream the stack retains and nothing fired"
	case OutcomeMissed:
		var unmet []string
		for _, x := range row.Expects {
			if !x.Met && x.Verdict == VerdictMustAlert {
				unmet = append(unmet, x.Kind+" "+x.ID)
			}
		}
		return "must-alert expectation(s) not met: " + strings.Join(unmet, ", ")
	}
	return row.Outcome
}

// cannotDistinguish is the refusal the indistinguishable miss meets, with
// the sentence that names the discipline: a gap to declare, not a rule to
// force.
func cannotDistinguish(sc *Scenario) string {
	return fmt.Sprintf("%s: every event its session emitted is identical to "+
		"its benign twin %s's on every closed field the rules may read (%s), "+
		"and a miss the telemetry cannot distinguish is a gap to declare, "+
		"not a rule to force", sc.ID, sc.Twin.ID,
		strings.Join(draftFieldNames(), ", "))
}

// firstTwinFire finds the first twin spool (in name order, for a
// deterministic record) the counts show firing above ambient.
func firstTwinFire(c *ruleCounts) (fired bool, spool string, fires int) {
	names := make([]string, 0, len(c.twins))
	for n := range c.twins {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if c.twins[n] > c.ambient {
			return true, n, c.twins[n] - c.ambient
		}
	}
	return false, "", 0
}

// leg is one placed event with the step it came from and the branch of the
// tree that matches it.
type leg struct {
	step   string
	event  telemetry.Event
	branch []detect.Match
	key    string
}

// signature is one event's branch of the tree: a comparison on every closed
// field the event carries, in the vocabulary's fixed order, with the label
// list split into one comparison per label the way the boundary writes it
// and the pack's own otel rules read it.
func signature(e telemetry.Event) ([]detect.Match, error) {
	f := e.Fields()
	var ms []detect.Match
	for _, df := range draftVocabulary {
		v, ok := f[df.field]
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		if !df.split {
			ms = append(ms, detect.Match{Field: df.field, Op: df.op,
				Values: []string{v}})
			continue
		}
		var labels []string
		for _, l := range strings.Split(v, ",") {
			if l = strings.TrimSpace(l); l != "" {
				labels = append(labels, l)
			}
		}
		sort.Strings(labels)
		for _, l := range labels {
			ms = append(ms, detect.Match{Field: df.field, Op: df.op,
				Values: []string{l}})
		}
	}
	if len(ms) == 0 {
		return nil, fmt.Errorf("an event from %s carries none of the closed "+
			"fields, so no honest tree can read it", e.Source)
	}
	return ms, nil
}

// branchKey is a branch's canonical form: the one order comparisons can be
// compared and sorted in.
func branchKey(ms []detect.Match) string {
	b, err := json.Marshal(ms)
	if err != nil {
		// Plain structs of strings; a marshal failure is not a condition a
		// caller can act on, and the empty key sorts first and fails loudly
		// in the equality it feeds.
		return ""
	}
	return string(b)
}

// derivation is what derive concluded about one scenario: the candidate rule
// (nil when the telemetry cannot distinguish the session from its twin), and
// the two counts that name what was separable and what stays declared.
type derivation struct {
	rule              *detect.Rule
	separable         int
	indistinguishable int
}

// derive is the drafting itself: the narrowest tree over the closed
// vocabulary that matches the session's separable events and refuses the
// twin's.
//
// Narrow means exactly this, and nothing wider is honest: each branch
// compares every closed field one event actually carried — equals on the
// value it carried, contains on each of its labels — with no field outside
// the vocabulary, no operator the pack does not use on that field, and no
// value no event held. The whole tree is the disjunction of the distinct
// branches the separable events need (one branch's conjunction when one is
// enough). No event is summarised, generalised or guessed at; the draft
// quotes the attack's own telemetry and nothing else.
//
// Separable means: no event of the benign twin produces the same branch. A
// session every one of whose branches the twin also produces cannot be told
// from honest work by any rule this vocabulary can carry, and derive returns
// a nil rule with the counts, for the caller to refuse by name.
func derive(sc *Scenario, base []telemetry.Event, anchor time.Time,
	seed int64) (*derivation, error) {

	attack, err := placedLegs(sc, sc.Steps, base, seed, anchor)
	if err != nil {
		return nil, err
	}
	twin, err := placedLegs(sc, sc.Twin.Steps, base, seed, anchor)
	if err != nil {
		return nil, err
	}

	twinBranches := map[string]bool{}
	for _, lg := range twin {
		twinBranches[lg.key] = true
	}

	// The session's legs, grouped by branch, in the order the session ran.
	type group struct {
		branch []detect.Match
		key    string
		legs   []leg
	}
	var groups []*group
	byKey := map[string]*group{}
	d := &derivation{}
	for _, lg := range attack {
		if twinBranches[lg.key] {
			d.indistinguishable++
			continue
		}
		g := byKey[lg.key]
		if g == nil {
			g = &group{branch: lg.branch, key: lg.key}
			byKey[lg.key] = g
			groups = append(groups, g)
		}
		g.legs = append(g.legs, lg)
		d.separable++
	}
	if len(groups) == 0 {
		return d, nil
	}
	// The branches' order is their own canonical form, so the tree is a
	// function of the session's shape and not of the order legs were walked.
	sort.Slice(groups, func(i, j int) bool { return groups[i].key < groups[j].key })

	subs := make([]detect.Predicate, 0, len(groups))
	for _, g := range groups {
		all := make([]detect.Predicate, len(g.branch))
		for i := range g.branch {
			m := g.branch[i]
			all[i] = detect.Predicate{Match: &m}
		}
		subs = append(subs, detect.Predicate{All: all})
	}
	var when detect.Predicate
	if len(subs) == 1 {
		when = subs[0]
	} else {
		when = detect.Predicate{Any: subs}
	}

	// The sources the separable legs actually came from, sorted — a rule
	// reads what it reads, and it reads only these.
	sources := map[string]bool{}
	var fixtures []detect.Fixture
	for _, g := range groups {
		for _, lg := range g.legs {
			sources[lg.event.Source] = true
			fixtures = append(fixtures, detect.Fixture{
				Name:  fmt.Sprintf("the session's %s leg", lg.step),
				Event: lg.event, Match: true})
		}
	}
	for _, lg := range twin {
		fixtures = append(fixtures, detect.Fixture{
			Name:  fmt.Sprintf("the twin's %s step", lg.step),
			Event: lg.event, Match: false})
	}
	srcs := make([]string, 0, len(sources))
	for s := range sources {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)

	d.rule = &detect.Rule{
		ID: "draft." + strings.TrimPrefix(sc.ID, "agent."),
		Title: fmt.Sprintf("The legs that separate %s from its benign twin",
			sc.ID),
		Why: fmt.Sprintf("drafted by the purple loop from %s's miss (%s): "+
			"the run's telemetry carried the session and no detection "+
			"alerted. The condition is the narrowest tree over the closed "+
			"vocabulary the boundary declares (%s) that matches the "+
			"session's separable event(s) and refuses every event of the "+
			"benign twin %s. The must-match fixtures are the scenario's own "+
			"events and the must-not-match fixtures are its twin's — the "+
			"discipline the pack's authors apply by hand, applied by the "+
			"loop to the exact bytes the run replayed. Nothing here is "+
			"deployed: a person promotes it by copying it into the pack on "+
			"the record, and the loop never writes the pack", sc.ID,
			missOf(sc), strings.Join(draftFieldNames(), ", "), sc.Twin.ID),
		Blind: fmt.Sprintf("%d of the session's %d event(s) are identical "+
			"to the twin's on every closed field and are invisible to any "+
			"rule this telemetry can honestly carry — that is the declared "+
			"gap, not a covered one. The tree quotes only the values this "+
			"one session's events carried, so the same end reached by other "+
			"tools or other labels is a new miss. And without the ordered "+
			"context of the detection that was missing it fires on the leg "+
			"alone, so its precision is exactly the twin's — one shape of "+
			"honest work, tested", d.indistinguishable, len(attack)),
		Sources:   srcs,
		When:      when,
		Severity:  telemetry.SeverityHigh,
		Technique: sc.Technique,
		Fixtures:  fixtures,
	}
	return d, nil
}

// missOf is a scenario's expectation list as a citation, for the why prose:
// what the scenario asked the pack for.
func missOf(sc *Scenario) string {
	parts := make([]string, 0, len(sc.Expects))
	for _, x := range sc.Expects {
		if x.Verdict == VerdictMustAlert {
			parts = append(parts, x.Kind+" "+x.ID+" not met")
		}
	}
	if len(parts) == 0 {
		return "no detection alerted on the session"
	}
	return strings.Join(parts, ", ")
}

// placedLegs re-derives a session's placed events and their step names from
// the same inputs the run used — the base stream as the ambient spool
// recorded it, the seed off the scorecard, the anchor off the base — so the
// fixtures are the exact bytes the run replayed, placed by the same
// deterministic arithmetic, not a copy that could drift from it.
func placedLegs(sc *Scenario, steps []Step, base []telemetry.Event,
	seed int64, anchor time.Time) ([]leg, error) {

	placed, err := Place(sc, steps, base, seed, anchor)
	if err != nil {
		return nil, err
	}
	expanded := expandSteps(steps)
	names := make([]string, len(expanded))
	seen := map[string]int{}
	for i, s := range expanded {
		seen[s.Name]++
		if n := seen[s.Name]; n > 1 {
			names[i] = fmt.Sprintf("%s, copy %d", s.Name, n)
			continue
		}
		names[i] = s.Name
	}
	out := make([]leg, 0, len(placed.Events))
	for i, e := range placed.Events {
		ms, err := signature(e)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", sc.ID, err)
		}
		out = append(out, leg{step: names[i], event: e, branch: ms,
			key: branchKey(ms)})
	}
	return out, nil
}

// countSteps is a session's expanded length, for the fixture counts.
func countSteps(steps []Step) int {
	n := 0
	for _, s := range steps {
		if s.Repeat != nil && s.Repeat.Count > 1 {
			n += s.Repeat.Count
			continue
		}
		n++
	}
	return n
}

// ruleCounts is one drafted rule's fires over every scratch spool the run
// wrote, split the way the three checks read them: the ambient spool (the
// base stream alone), each scenario's own spool, each twin's.
type ruleCounts struct {
	ambient  int
	scenario map[string]int
	twins    map[string]int
	replay   []SpoolFires
}

// replayCounts replays the derived rules over every scratch spool once: the
// whole run's evidence, re-read through the run's own replay pass (runPass —
// the same compiled rules, the same walk, no forked engine), with the drafts
// instead of the pack.
//
// This is the second half of the loop's honesty: the fixtures prove the
// draft on the session's own events, and this proves it on the streams the
// scorecard attests — the estate's traffic alone, every twin's, every other
// scenario's session. The watermark budget feeds only the correlations, and
// a draft ships none, so the pass runs with a nominal one.
func replayCounts(card *Scorecard, derived map[string]*derivation) (
	map[string]*ruleCounts, error) {

	draftRef := &Reference{Name: "purple-drafts",
		ruleQuiet: map[string]bool{}, corrIDs: map[string]bool{}}
	counts := map[string]*ruleCounts{}
	for _, d := range derived {
		if d.rule == nil {
			continue
		}
		draftRef.Rules = append(draftRef.Rules, *d.rule)
		draftRef.ruleQuiet[strings.ToLower(d.rule.ID)] = false
		counts[d.rule.ID] = &ruleCounts{scenario: map[string]int{},
			twins: map[string]int{}}
	}
	if len(draftRef.Rules) == 0 {
		return counts, nil
	}
	sort.Slice(draftRef.Rules, func(i, j int) bool {
		return draftRef.Rules[i].ID < draftRef.Rules[j].ID
	})

	entries, err := os.ReadDir(card.Scratch)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		// The variants a run under mutation wrote are respellings of
		// sessions whose own spools are already here; replaying a draft
		// over them would count one session as many.
		if e.IsDir() && e.Name() != mutantsDir {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		sp, err := spool.Open(filepath.Join(card.Scratch, d), spool.Options{})
		if err != nil {
			return nil, fmt.Errorf("the scratch spool %s: %w", d, err)
		}
		res, err := runPass(sp, draftRef, time.Second)
		sp.Close()
		if err != nil {
			return nil, fmt.Errorf("replaying the drafts over %s: %w", d, err)
		}
		// The label a reader sees: the base stream, a scenario's own spool,
		// or its twin's — the run's own directory naming, so the record
		// speaks the scorecard's dialect.
		for id := range counts {
			fires := res.loud[id]
			c := counts[id]
			switch {
			case d == "ambient":
				c.ambient = fires
				c.replay = append(c.replay,
					SpoolFires{Spool: "base", Fires: fires})
			case strings.HasSuffix(d, "--twin"):
				c.twins[d] = fires
				c.replay = append(c.replay,
					SpoolFires{Spool: strings.TrimSuffix(d, "--twin") +
						" (twin)", Fires: fires})
			default:
				c.scenario[d] = fires
				c.replay = append(c.replay,
					SpoolFires{Spool: d, Fires: fires})
			}
		}
	}
	for _, c := range counts {
		sort.Slice(c.replay, func(i, j int) bool {
			return c.replay[i].Spool < c.replay[j].Spool
		})
	}
	return counts, nil
}

// readScratchSpool reads a scratch spool's whole stream back as events.
func readScratchSpool(dir string) ([]telemetry.Event, error) {
	sp, err := spool.Open(dir, spool.Options{})
	if err != nil {
		return nil, err
	}
	defer sp.Close()
	var out []telemetry.Event
	if err := sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		out = append(out, e)
		return nil
	}); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s holds no events", dir)
	}
	return out, nil
}

// ruleDocument renders a draft in the pack's own file conventions —
// indented, HTML unescaped, one field per line — so promoting it is copying
// it, byte for byte, and nothing reshapes it on the way in.
func ruleDocument(v any) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// writeDraftRecord writes one audit record beside the proposals it describes.
func writeDraftRecord(dir, name string, rec DraftRecord) error {
	body, err := ruleDocument(rec)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), body, 0o600)
}
