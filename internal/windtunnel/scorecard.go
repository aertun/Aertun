// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aertun/aertun/internal/jcs"
)

// The scorecard: the document a run writes, seals, and (when a key was
// supplied) signs; the file a third party verifies offline.
//
// Shaped like aertunbench's Results (internal/bench/run.go): it names what
// ran — corpus, digests, pack, mode, engine — before how it went, because a
// number without those names is a claim rather than a measurement. And it
// carries what the results document honestly says it lacks: dual signatures
// on day one, in this package's own context (decision 7).
const (
	// DocSchema is the schema a run writes. Version 2 digests and signs the
	// document's RFC 8785 canonical form (internal/jcs), so a verifier in
	// any language with a conforming canonicaliser recomputes the signed
	// bytes from the data, rather than having to be this build's encoder
	// with this build's field order. A document from a schema this build
	// does not know is refused rather than best-effort rendered.
	DocSchema = "aertun/windtunnel-scorecard/v2"
	// DocSchemaV1 is the schema earlier builds wrote, whose digest covers
	// encoding/json's compact output in declaration order. This build
	// still verifies it — the published history and the committed seed
	// card are version 1, and a signature that stopped verifying when the
	// verifier upgraded would be a history nobody can check — and never
	// writes it.
	DocSchemaV1 = "aertun/windtunnel-scorecard/v1"
	// Engine is the wind tunnel engine's own version: bumped when the
	// splicing or scoring semantics change, because a scorecard's numbers
	// are only comparable against the engine that produced them.
	Engine = "windtunnel-1"
)

// The standing of a scoring mode: which question its numbers answer.
//
// Their rules are the primary mode, because a scenario corpus written
// without sight of an organisation's rules is a test of those rules. The
// shipped reference pack is the secondary mode and is self-graded: the
// scenarios were written beside its rules, so a reference run is a
// regression test of the pack, not a measurement of anybody's controls,
// and every screen that shows its result says so.
const (
	StandingPrimary    = "primary"
	StandingSelfGraded = "secondary-self-graded"
)

// standingOf is a scoring mode's standing.
func standingOf(scoreMode string) string {
	if modeOf(scoreMode) == ModeReference {
		return StandingSelfGraded
	}
	return StandingPrimary
}

// ModeStanding is the standing of the document's scoring mode, for a
// version 1 document as for a version 2 one: it is derived from the mode,
// which both versions seal.
func (c *Scorecard) ModeStanding() string { return standingOf(c.ScoreMode) }

// standingLine is a scoring mode's standing as a sentence a person reads
// under the line that names the mode.
func standingLine(scoreMode string) string {
	if standingOf(scoreMode) == StandingSelfGraded {
		return "the shipped reference pack — the secondary mode, and " +
			"self-graded: the scenarios were written beside these rules, so " +
			"this is a regression test of the pack, not a measurement of " +
			"anybody's controls. Score your own rules with --sigma DIR, the " +
			"primary mode"
	}
	return "your own rules — the primary mode: rules the scenarios were " +
		"not written against, replayed under this engine"
}

// selfGradedMark follows every result line of a self-graded document, so
// a number quoted from a reference run carries its standing with it.
func selfGradedMark(scoreMode string) string {
	if standingOf(scoreMode) == StandingSelfGraded {
		return " [self-graded: secondary mode]"
	}
	return ""
}

// attributionCaveat is stated on every document, in the blind tradition: a
// replay has no detection wall-clock, and the number that stands in for one
// is a property of the rule windows, not of anybody's shifts.
const attributionCaveat = "Attribution times are event-time-to-attribution: " +
	"the gap between the step that completed a pattern and the window that " +
	"attributed it. They are a property of the rule windows, not of a SOC's " +
	"shifts — a replay has no detection wall-clock, and nothing here should " +
	"be read as a response-time promise."

// ExpectRow is one expectation's verdict.
type ExpectRow struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Verdict string `json:"verdict"`
	Met     bool   `json:"met"`
	// Fires is the count above ambient: what this session added.
	Fires int `json:"fires"`
	// MissKind says which kind of miss a missed must-alert was.
	MissKind string `json:"miss_kind,omitempty"`
	// AttributionSecs is the event-time-to-attribution for a met must-alert
	// expectation; zero for a rule, whose match is the event itself.
	AttributionSecs float64 `json:"attribution_secs,omitempty"`
	// Note carries the honest particulars: a lateness miss's count, a
	// deleted rule's absence.
	Note string `json:"note,omitempty"`
}

// TwinOutcome is the benign twin's result: the precision axis.
type TwinOutcome struct {
	ID            string `json:"id"`
	Outcome       string `json:"outcome"`
	SessionEvents int    `json:"session_events"`
}

// Row is one scenario's whole result.
type Row struct {
	Scenario string `json:"scenario"`
	Digest   string `json:"digest"`
	Family   string `json:"family"`
	// Techniques are what this scenario stages, for the coverage grid.
	Techniques []string `json:"technique"`
	Outcome    string   `json:"outcome"`
	// SessionEvents is how many events the spliced session expanded to.
	SessionEvents int         `json:"session_events"`
	Expects       []ExpectRow `json:"expects"`
	Twin          TwinOutcome `json:"twin"`
	// Note carries a their-mode row's join particulars: a scenario nothing
	// of theirs tags, fires the join recorded but could not credit.
	Note string `json:"note,omitempty"`
}

// missKind is the scenario-level miss kind: the lateness kind when any
// missed correlation reported it, else a content miss.
func (r *Row) MissKind() string {
	for _, x := range r.Expects {
		if !x.Met && x.MissKind == MissLateness {
			return MissLateness
		}
	}
	return MissContent
}

// ScenarioDigest names one scenario and the exact bytes it came from.
type ScenarioDigest struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Twin   string `json:"twin"`
}

// Blind is one scenario's declared blind spot, restated on the document so
// the reader of a number can read what the number does not cover.
type Blind struct {
	Scenario string `json:"scenario"`
	Blind    string `json:"blind"`
}

// Aggregate is the scorecard's numbers: the primary miss rate with its
// Wilson bounds, and the counts that qualify it.
type Aggregate struct {
	Scenarios int `json:"scenarios"`
	// MustAlert is the denominator: scenarios carrying a must-alert
	// expectation, the only ones a miss rate may be read over.
	MustAlert int `json:"must_alert_scenarios"`
	Missed    int `json:"missed"`
	// MissedLateness splits the misses: windows that closed before the
	// completing event arrived.
	MissedLateness int `json:"missed_lateness"`
	Caught         int `json:"caught_alert"`
	TelemetryOnly  int `json:"caught_telemetry_only"`
	WronglyQuiet   int `json:"wrongly_quiet"`
	TwinFires      int `json:"twin_false_fires"`

	MissRate     float64 `json:"miss_rate"`
	MissRateLow  float64 `json:"miss_rate_wilson_low"`
	MissRateHigh float64 `json:"miss_rate_wilson_high"`
}

// FamilyRow is the family grid: what ran, per family.
type FamilyRow struct {
	Family        string `json:"family"`
	Tested        int    `json:"tested"`
	Caught        int    `json:"caught_alert"`
	Missed        int    `json:"missed"`
	TelemetryOnly int    `json:"telemetry_only"`
	WronglyQuiet  int    `json:"wrongly_quiet"`
	TwinFires     int    `json:"twin_false_fires"`
}

// TechniqueRow is the technique grid. Caught means a scenario that stages
// the technique was caught at alert tier — and per the pack's own rule
// comments, a technique marked covered does not reveal whether detections
// reliably identify all its variations; the grid is navigation, never a
// score.
type TechniqueRow struct {
	Technique string `json:"technique"`
	Tested    int    `json:"tested"`
	Caught    int    `json:"caught"`
}

// Scorecard is the sealed document. Field order is the reading order: what
// ran, then what happened.
type Scorecard struct {
	Schema    string `json:"schema"`
	Mode      string `json:"mode"`
	Engine    string `json:"engine"`
	ScoreMode string `json:"score_mode"`
	// Standing is the scoring mode's standing, sealed with the numbers so
	// a reader of the file alone knows whether they are self-graded.
	// Version 2 only; Verify holds it to the mode.
	Standing string `json:"standing,omitempty"`
	Corpus   string `json:"corpus"`
	Seed     int64  `json:"seed"`

	Base       string `json:"base"`
	BaseDigest string `json:"base_digest"`
	BaseEvents int    `json:"base_events"`
	Pack       string `json:"pack"`
	PackDigest string `json:"pack_digest"`

	Scenarios []ScenarioDigest `json:"scenarios"`

	Rows       []Row          `json:"rows"`
	Aggregate  *Aggregate     `json:"aggregate"`
	Families   []FamilyRow    `json:"families"`
	Techniques []TechniqueRow `json:"techniques"`
	// Heatmap is the technique-by-scenario grid, the same rows as words in
	// a square: every cell an outcome word, every row its margin counts,
	// nothing perceivable only by colour. Sealed with the rest, because a
	// grid that drifted from its rows would be a second opinion.
	Heatmap []HeatRow `json:"heatmap,omitempty"`
	Blinds  []Blind   `json:"blinds"`
	Caveat  string    `json:"caveat"`

	// TheirSigma is the import report when the run scored the
	// organisation's own Sigma rules: what was read, what imported, what
	// was refused with the construct named. Counted, never silently
	// dropped — the refusal is a result.
	TheirSigma *SigmaReport `json:"their_sigma,omitempty"`
	// ModeBlind is the scoring mode's own fidelity limit, in the blind
	// tradition: their-Sigma documents state the technique-join limit; a
	// reference document needs none, because the id join has no join to
	// caveat.
	ModeBlind string `json:"mode_blind,omitempty"`
	// AmbientFires is what the instrument raised over the base stream
	// alone — the estate's own alerts. Zero on the quiet morning the
	// fixture is; whatever it is, it is sealed, so a diff can tell a rules
	// finding from an estate finding.
	AmbientFires int `json:"ambient_fires,omitempty"`

	// Mutation is the run under mutation, when one was asked for: each
	// scenario's session respelled and replayed again (mutate.go). Version
	// 2 only.
	Mutation *MutationReport `json:"mutation,omitempty"`

	// Scratch names where the scratch spools were written, so an operator
	// can inspect the exact streams that were scored.
	Scratch     string    `json:"scratch"`
	GeneratedAt time.Time `json:"generated_at"`

	// SHA256 is the document's own digest, over the canonical form with the
	// digest empty and the signature absent: a check against sloppiness, so
	// a rendered number can be traced to the file it came from and an edited
	// file refuses to render. The signature is the check against forgery.
	SHA256 string `json:"sha256"`
	// Signature is both algorithms over that digest, in this package's own
	// context. Nil on an unsigned document, which says so when rendered.
	Signature *ScorecardSignature `json:"signature,omitempty"`
}

// digestBytes is the canonical form a digest is taken over and a signature
// covers: the whole document, digest empty and signature absent, in the
// form its schema names. The receiver is not mutated, so verifying a signed
// document does not strip its own signature.
func (c *Scorecard) digestBytes() ([]byte, error) {
	body := *c
	body.SHA256 = ""
	body.Signature = nil
	switch c.Schema {
	case DocSchema:
		return canonicalBytes(&body)
	case DocSchemaV1:
		return legacyBytes(&body)
	}
	return nil, fmt.Errorf("the document's schema is %q; this build reads "+
		"%q and %q", c.Schema, DocSchema, DocSchemaV1)
}

// canonicalBytes is version 2's form: the RFC 8785 canonical form of the
// document's JSON.
//
// Then the round trip. RFC 8785 reads every number as a double, so an
// integer wider than 53 bits — a seed, a count — would be signed as its
// neighbour, and two documents that render different numbers would share
// one digest and one signature. The canonical bytes are therefore decoded
// back and must re-encode to exactly the document that went in; one that
// does not is refused rather than sealed, and a document someone edited
// into that shape is refused rather than verified.
func canonicalBytes(body *Scorecard) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	canon, err := jcs.Canonicalize(raw)
	if err != nil {
		return nil, err
	}
	var back Scorecard
	if err := json.Unmarshal(canon, &back); err != nil {
		return nil, err
	}
	again, err := json.Marshal(&back)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, again) {
		return nil, fmt.Errorf("the scorecard's canonical form does not " +
			"decode to the document it came from: it carries a number a " +
			"double cannot hold exactly (an integer wider than 53 bits — " +
			"RFC 8785 section 3.1), which would be signed as a different " +
			"number. Seeds and counts stay within ±9007199254740991")
	}
	return canon, nil
}

// legacyBytes is version 1's form, kept for verification only: compact
// JSON from Go's encoder, fields in declaration order, HTML unescaped.
// Every field version 2 added is omitempty and empty on a version 1
// document (Verify refuses one that carries them), so this is byte for
// byte what the builds that wrote version 1 digested.
func legacyBytes(body *Scorecard) ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(buf.String(), "\n")), nil
}

// seal fills the document's own digest. Called before any signature is
// made: the signature covers the digest, and the digest covers everything
// else, so an edit anywhere is caught twice.
func (c *Scorecard) seal() error {
	b, err := c.digestBytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	c.SHA256 = hex.EncodeToString(sum[:])
	return nil
}

// Verify checks a document against its own digest, and its schema. This is
// the check a rendered number can be traced by; the signature check is
// VerifyScorecard's, and the verify entry point runs both.
func (c *Scorecard) Verify() error {
	switch c.Schema {
	case DocSchema:
		// The standing is sealed with the numbers, and it must be the
		// mode's: a reference document relabelled primary would be a
		// self-graded number wearing an independent one's name.
		if c.Standing != standingOf(c.ScoreMode) {
			return fmt.Errorf("the document scored %s and calls itself %q; "+
				"that mode's standing is %q", c.ScoreMode, c.Standing,
				standingOf(c.ScoreMode))
		}
	case DocSchemaV1:
		// Version 1 had no standing and no mutation section. A version 1
		// document carrying either was not written by a version 1 build,
		// and its legacy digest would cover fields no version 1 signer
		// ever saw.
		if c.Standing != "" || c.Mutation != nil {
			return fmt.Errorf("the document says it is %s and carries "+
				"fields that schema never had; it was not written by a "+
				"build that wrote %s", DocSchemaV1, DocSchemaV1)
		}
	default:
		return fmt.Errorf("the document's schema is %q; this build reads "+
			"%q and %q", c.Schema, DocSchema, DocSchemaV1)
	}
	b, err := c.digestBytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	got := hex.EncodeToString(sum[:])
	if got != c.SHA256 {
		return fmt.Errorf("the document's digest is %s and its contents hash "+
			"to %s: it has been edited since it was written, and nothing "+
			"rendered from it can be cited", c.SHA256, got)
	}
	return nil
}

// Document renders the scorecard as the bytes a run writes: indented, HTML
// unescaped, one field per line — the same conventions as the results
// document, so a scorecard diffs the way the corpus diffs.
func (c *Scorecard) Document() ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// shortDigest is a digest the way a person compares one.
func shortDigest(d string) string {
	if len(d) <= 12 {
		return d
	}
	return d[:12] + "…"
}

// pct is a rate the way a person reads one at a glance.
func pct(v float64) string { return fmt.Sprintf("%.1f%%", v*100) }

// Summarize is the run in words, for a terminal: what ran first, then the
// per-scenario tiers, then the aggregate with its bounds, then the grids,
// the twins, the blinds — one screen a founder can read, one file an
// insurer can verify. Nothing here is a claim the document does not carry.
func (c *Scorecard) Summarize() string {
	var b strings.Builder
	fmt.Fprintf(&b, "wind tunnel, mode %s, scoring %s, engine %s\n", c.Mode,
		c.ScoreMode, c.Engine)
	b.WriteString(hang("  scored by ", standingLine(c.ScoreMode)))
	fmt.Fprintf(&b, "  base stream %s (%d event(s), digest %s)\n", c.Base,
		c.BaseEvents, shortDigest(c.BaseDigest))
	fmt.Fprintf(&b, "  reference pack %s (digest %s), corpus %s, seed %d\n",
		c.Pack, shortDigest(c.PackDigest), c.Corpus, c.Seed)
	if ts := c.TheirSigma; ts != nil {
		// The import accounting, first-class: what was read, what imported,
		// what refused with the construct named. A refused rule cannot
		// catch anything, and a scorecard that dropped it silently would
		// be reporting on a library it did not read.
		fmt.Fprintf(&b, "  their Sigma rules %s (digest %s): %d read, %d "+
			"imported, %d refused at import — refused constructs are "+
			"counted, never dropped\n", ts.Dir, shortDigest(ts.Digest),
			ts.Read, ts.Imported, len(ts.Refused))
		for _, s := range ts.Refused {
			b.WriteString(hang(fmt.Sprintf("      refused %q: ", s.Rule),
				s.What+" — "+refusalWhy(s)))
		}
	}
	for _, s := range c.Scenarios {
		fmt.Fprintf(&b, "      %-40s %s (twin %s)\n", s.ID,
			shortDigest(s.Digest), s.Twin)
	}
	fmt.Fprintf(&b, "  %d scenario(s):\n", len(c.Rows))
	for _, r := range c.Rows {
		note := ""
		switch {
		case r.Outcome == OutcomeMissed && r.MissKind() == MissLateness:
			note = " (lateness: the window closed before the completing " +
				"event arrived)"
		case r.Outcome == OutcomeMissed:
			note = " (content)"
		}
		fmt.Fprintf(&b, "    %-38s %-18s%s\n", r.Scenario, r.Outcome, note)
		for _, x := range r.Expects {
			mark := "met"
			if !x.Met {
				mark = "UNMET"
			}
			fmt.Fprintf(&b, "        %-12s %-28s %-14s %s", x.Kind, x.ID,
				x.Verdict, mark)
			if x.Verdict == VerdictMustAlert && x.Met {
				if x.Kind == ExpectRule {
					fmt.Fprintf(&b, ", matched at the event")
				} else {
					fmt.Fprintf(&b, ", attributed %.0fs after the completing step",
						x.AttributionSecs)
				}
			}
			if x.Note != "" {
				fmt.Fprintf(&b, "\n            %s", x.Note)
			}
			fmt.Fprintf(&b, "\n")
		}
		twin := "quiet"
		if r.Twin.Outcome == TwinFalseFire {
			twin = "FALSE FIRE"
		}
		fmt.Fprintf(&b, "        twin %-38s %s\n", r.Twin.ID, twin)
		if r.Note != "" {
			b.WriteString(hang("        ", r.Note))
		}
	}
	a := c.Aggregate
	fmt.Fprintf(&b, "  missed %d of %d must-alert scenario(s) (%s, 95%% "+
		"Wilson %.1f%% to %.1f%%)%s\n", a.Missed, a.MustAlert,
		pct(a.MissRate), a.MissRateLow*100, a.MissRateHigh*100,
		selfGradedMark(c.ScoreMode))
	fmt.Fprintf(&b, "  %d caught at alert, %d telemetry-only, %d "+
		"wrongly-quiet; %d of the misses were lateness\n", a.Caught,
		a.TelemetryOnly, a.WronglyQuiet, a.MissedLateness)
	fmt.Fprintf(&b, "  benign twins: %d false fire(s) of %d\n", a.TwinFires,
		a.Scenarios)
	if c.AmbientFires > 0 {
		fmt.Fprintf(&b, "  ambient: %d alert(s) on the base stream alone; "+
			"every count above subtracts them\n", c.AmbientFires)
	}
	if c.Mutation != nil {
		renderMutation(&b, c.Mutation, selfGradedMark(c.ScoreMode))
	}
	fmt.Fprintf(&b, "  families: ")
	for i, f := range c.Families {
		if i > 0 {
			fmt.Fprintf(&b, ", ")
		}
		fmt.Fprintf(&b, "%s %d/%d", f.Family, f.Caught, f.Tested)
	}
	fmt.Fprintf(&b, "\n  techniques: ")
	for i, t := range c.Techniques {
		if i > 0 {
			fmt.Fprintf(&b, ", ")
		}
		fmt.Fprintf(&b, "%s %d/%d", t.Technique, t.Caught, t.Tested)
	}
	fmt.Fprintf(&b, "\n")
	renderHeatmap(&b, c.Heatmap)
	if len(c.Blinds) > 0 {
		fmt.Fprintf(&b, "  declared blinds:\n")
		for _, bl := range c.Blinds {
			b.WriteString(hang("    "+bl.Scenario+": ", bl.Blind))
		}
	}
	if c.ModeBlind != "" {
		b.WriteString(hang("  scoring blind: ", c.ModeBlind))
	}
	b.WriteString(hang("  ", c.Caveat))
	sig := "unsigned: no key was supplied, and this document makes no claim " +
		"a signature would back"
	if c.Signature != nil {
		sig = "dual-signed (Ed25519 and ML-DSA-65) by key " +
			c.Signature.KeyID + ", context " + ScorecardContext
	}
	fmt.Fprintf(&b, "  %s\n  document sha256 %s; generated %s; scratch %s\n",
		sig, shortDigest(c.SHA256),
		c.GeneratedAt.Format(time.RFC3339), c.Scratch)
	return b.String()
}

// renderMutation is the mutation section of the summary: what each
// scenario's variants did, then the two rates as k of n with their bounds —
// or, when no variant of a must-alert scenario could be made, the sentence
// that says there is no rate rather than a 0% over nothing.
func renderMutation(b *strings.Builder, m *MutationReport, mark string) {
	fmt.Fprintf(b, "  under mutation, %d variant(s) asked for per scenario, "+
		"respelling only what the attacker spells:\n", m.Requested)
	for _, r := range m.Rows {
		if r.Variants == 0 {
			fmt.Fprintf(b, "    %-38s no variant (%s unmutated)\n",
				r.Scenario, r.Original)
		} else {
			fmt.Fprintf(b, "    %-38s %s unmutated; %d variant(s): %d "+
				"caught, %d missed", r.Scenario, r.Original, r.Variants,
				r.Caught, r.Missed)
			if r.TelemetryOnly > 0 || r.WronglyQuiet > 0 {
				fmt.Fprintf(b, ", %d telemetry-only, %d wrongly-quiet",
					r.TelemetryOnly, r.WronglyQuiet)
			}
			fmt.Fprintf(b, "\n        respelled %s; variants sha256 %s\n",
				strings.Join(r.Surface, ", "), shortDigest(r.Digest))
		}
		if r.Note != "" {
			b.WriteString(hang("        ", r.Note))
		}
	}
	if x := m.MissUnderMutation; x != nil {
		fmt.Fprintf(b, "  missed %d of %d variant(s) of must-alert "+
			"scenarios (%s, 95%% Wilson %.1f%% to %.1f%%)%s\n", x.K, x.N,
			pct(x.Rate), x.Low*100, x.High*100, mark)
	} else {
		fmt.Fprintf(b, "  no variant of a must-alert scenario could be "+
			"made, so there is no miss rate under mutation to state\n")
	}
	if x := m.Evasion; x != nil {
		fmt.Fprintf(b, "  of the variants of scenarios caught unmutated, %d "+
			"of %d evaded (%s, 95%% Wilson %.1f%% to %.1f%%)%s\n", x.K, x.N,
			pct(x.Rate), x.Low*100, x.High*100, mark)
	}
	b.WriteString(hang("  mutation caveat: ", m.Caveat))
}

// hang is one paragraph for the terminal, ending in a newline: lead as it
// is given, then the sentence, broken at 78 columns, with every line after
// the first hung two spaces inside the lead's own indent — so a note that
// wraps stays under what it is a note about, at whatever depth that is.
func hang(lead, s string) string {
	const width = 78
	pad := strings.Repeat(" ", len(lead)-len(strings.TrimLeft(lead, " "))+2)
	var b strings.Builder
	line, bare := lead, true
	for _, w := range strings.Fields(s) {
		switch {
		case bare:
			line += w
			bare = false
		case utf8.RuneCountInString(line)+1+utf8.RuneCountInString(w) > width:
			b.WriteString(line + "\n")
			line = pad + w
		default:
			line += " " + w
		}
	}
	b.WriteString(strings.TrimRight(line, " ") + "\n")
	return b.String()
}
