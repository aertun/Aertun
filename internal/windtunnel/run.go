// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/correlate"
	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// The run: splice, replay, join, score.
//
// The replay is the shadow replay's shape (internal/pack/shadow.go), which is
// the detect run's shape minus everything that writes: the reference pack's
// rules compiled once and asked of every event in arrival order, the
// correlations' engines fed from the matches, and nothing recorded in any
// finding register, no cursor moved, no suppression consulted. The wind
// tunnel has no findings to raise — it is measuring the raising.
//
// # Where this replay is stricter than the shadow
//
// The shadow replays with no watermark on the way in and closes at the end —
// right for asking "what would the last seven days have raised". The wind
// tunnel asks a different question — did the controls catch this session —
// and answers it with the live system's own semantics: each event is observed
// against the watermark its arrivals have earned (newest arrival less the
// observed 99th-percentile delay, the run's own rule), so an event that
// lands after its window closed is dropped and counted late exactly as the
// live engine drops and counts it. Then, the recording being over, the
// windows still open are decided — the live system's later runs would close
// every one of them, and nothing further can arrive in a replay. A miss
// caused by that drop is a lateness miss, and the scorecard says which kind
// of miss it was: a finding about the lateness budget, not about the rules.

// passResult is what one replay of the rules over one stream found.
type passResult struct {
	events int
	// loud counts loud rule fires; quiet counts quiet rule matches, which
	// raise nothing themselves and are the correlations' to count.
	loud  map[string]int
	quiet map[string]int
	// hits is each correlation's met windows; late is how many events the
	// engine dropped because their window had already closed.
	hits map[string][]correlate.Hit
	late map[string]int
	// matched remembers which rules each placed event matched, for the
	// attribution arithmetic. Keyed by the event's arrival instant.
	matched map[time.Time][]string
}

// runPass replays the reference pack over a scratch spool's whole stream.
//
// budget is the arrival delay the watermark waits behind — the 99th
// percentile of the stream's own observed lateness, computed by the caller
// from the same stream.
func runPass(sp *spool.Spool, ref *Reference, budget time.Duration) (*passResult, error) {
	progs := make([]*detect.Program, 0, len(ref.Rules))
	for _, r := range ref.Rules {
		p, err := r.Compile()
		if err != nil {
			return nil, fmt.Errorf("%s cannot be replayed: %w", r.ID, err)
		}
		progs = append(progs, p)
	}
	engines := make([]*correlate.Engine, 0, len(ref.Corrs))
	for _, c := range ref.Corrs {
		e, err := correlate.New(c)
		if err != nil {
			return nil, fmt.Errorf("%s cannot be replayed: %w", c.ID, err)
		}
		engines = append(engines, e)
	}

	res := &passResult{loud: map[string]int{}, quiet: map[string]int{},
		hits: map[string][]correlate.Hit{}, late: map[string]int{},
		matched: map[time.Time][]string{}}
	wm := time.Time{}
	err := sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		res.events++
		// The watermark this arrival has earned: everything older than the
		// stream's own 99th-percentile delay has been delivered.
		if w := e.Received.Add(-budget); w.After(wm) {
			wm = w
		}
		f := e.Fields()
		for _, p := range progs {
			if !p.MatchesFields(e.Source, f) {
				continue
			}
			if p.Quiet {
				res.quiet[p.ID]++
			} else {
				res.loud[p.ID]++
			}
			res.matched[e.Received] = append(res.matched[e.Received], p.ID)
			for _, eng := range engines {
				if !eng.Watches(p.ID) {
					continue
				}
				if oerr := eng.Observe(correlate.Seen{Rule: p.ID, Event: e},
					wm); oerr != nil {
					return oerr
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, eng := range engines {
		res.hits[eng.Rule().ID] = eng.Flush()
		res.late[eng.Rule().ID] = eng.Late()
	}
	return res, nil
}

// The outcome tiers, categorical in the MITRE Evaluations tradition:
// recorded, never dressed up as a number (decision 4). Telemetry is never
// counted as caught; a miss says which kind it was; the twin axis is
// reported beside, not folded in.
const (
	// OutcomeCaughtAlert: a named detection alerted within the window.
	OutcomeCaughtAlert = "caught-alert"
	// OutcomeCaughtTelemetry: the events are visible in the stream the stack
	// retains and nothing alerted. Recorded, never counted as caught.
	OutcomeCaughtTelemetry = "caught-telemetry"
	// OutcomeMissed: no detection, and the scorecard says whether the window
	// closed before the completing event arrived.
	OutcomeMissed = "missed"
	// OutcomeWronglyQuiet: a declared-quiet leg fired. A stack that alerts
	// on every untrusted read is drowning its analysts — Axelsson again.
	OutcomeWronglyQuiet = "wrongly-quiet"
)

// The twin's outcome: quiet, or the precision axis failed.
const (
	TwinQuiet     = "quiet"
	TwinFalseFire = "false-fire"
)

// The miss kinds: a lateness miss is a finding about the watermark budget,
// a content miss is a finding about the rules. Conflating them is how a
// replay flatters itself.
const (
	MissLateness = "lateness"
	MissContent  = "content"
)

// The scoring modes (decision 6). their-Sigma mode is the primary one: it
// imports the organisation's own rules through the existing importer and
// joins at technique level, with the join's fidelity limit stated on every
// document it seals. Reference mode scores the shipped pack, whose rules
// the scenarios were written beside, so it is the secondary mode and
// self-graded — a regression test of the pack — and every document and
// screen of it says so (StandingSelfGraded). It stays the default when no
// instrument is named, so existing callers keep working. their-alerts is
// named so its refusal is a named refusal, not a missing feature.
const (
	ModeReference  = "reference"
	ModeTheirSigma = "their-sigma"
	ModeTheirAlert = "their-alerts"
)

// RunOptions is what a run needs. Nothing in it opens the live store: the
// base stream is a file or the embedded fixture, the scratch spool is a
// directory the operator named or a fresh temporary one, and the only key
// read is one the operator pointed at.
type RunOptions struct {
	// Scenarios names scenario ids; empty means the whole seed corpus.
	Scenarios []string
	// Base is the recorded base stream: a JSONL file, a directory of spool
	// segments, or empty for the embedded fixture. A live endpoint here is
	// refused by code (decision 8) — replay is the safety story, and phase 1
	// has no live mode to be talked into.
	Base string
	// Into is the scratch root. Empty means a fresh temporary directory.
	Into string
	// Seed moves the clocks — the arrival-delay draws — and nothing else:
	// the session identities come from the scenario files, so a digest names
	// the same session whatever seed it ran under.
	Seed int64
	// ScoreMode is the scoring mode; empty means reference.
	ScoreMode string
	// Now stamps the document.
	Now time.Time
	// Reference overrides the shipped pack as the instrument. Nil loads the
	// shipped pack. When set, the corpus is shape-checked rather than
	// co-validated: the strict co-test is the shipped pack's own fixture
	// discipline, and a different instrument — the doctored reference a test
	// scores, a pack a third party hands over — meets the scorecard's
	// honesty rules instead, where every expectation the instrument lacks is
	// reported as the miss it is. Nothing else about the run moves.
	Reference *Reference
	// Signer, when set, dual-signs the sealed scorecard in the wind tunnel's
	// own context. Nil writes an unsigned document that says so.
	Signer *pack.Key
	// Mutate is how many effect-preserving respellings of each scenario's
	// session to replay besides the session itself (mutate.go), at most
	// MaxMutate. Zero runs no variants and writes no mutation section.
	Mutate int
}

// Run splices, replays, joins and scores, and returns the sealed scorecard.
func Run(opts RunOptions) (*Scorecard, error) {
	// The live-target refusal, in code. A URL where a stream path belongs is
	// somebody asking the wind tunnel to fire at a staging collector, and no
	// scenario this build can load is allowed there: they are all
	// synthetic-only, replay is the whole safety story, and the refusal is
	// here rather than in the CLI so no caller can route around it.
	for _, prefix := range []string{"http://", "https://", "otlp://", "grpc://"} {
		if strings.HasPrefix(strings.ToLower(opts.Base), prefix) {
			return nil, fmt.Errorf("refused: %s names a live endpoint, and "+
				"every scenario this build loads is synthetic-only — replay "+
				"is the safety story, by construction. Live targets arrive "+
				"with phase 3's containment, and nothing in this build can "+
				"be configured into them", opts.Base)
		}
	}
	if opts.Mutate < 0 || opts.Mutate > MaxMutate {
		return nil, fmt.Errorf("%d variants per scenario were asked for; "+
			"mutation runs between 0 and %d, enough to show a rule's "+
			"failure modes and few enough to stay a CI step", opts.Mutate,
			MaxMutate)
	}
	mode := opts.ScoreMode
	if mode == "" {
		mode = ModeReference
	}
	var theirs *theirSigma
	switch {
	case mode == ModeReference:
	case strings.HasPrefix(mode, ModeTheirSigma+":"):
		dir := strings.TrimSpace(strings.TrimPrefix(mode, ModeTheirSigma+":"))
		if dir == "" {
			return nil, fmt.Errorf("%s scoring names no directory: the mode "+
				"is %s:DIR (or run --sigma DIR), where DIR is the "+
				"organisation's Sigma rules", ModeTheirSigma, ModeTheirSigma)
		}
		loaded, err := loadTheirSigma(dir)
		if err != nil {
			return nil, err
		}
		theirs = loaded
	case strings.HasPrefix(mode, ModeTheirAlert+":"):
		return nil, fmt.Errorf("%s scoring arrives in phase 2: it reads the "+
			"organisation's alert output for the replay window in OCSF and "+
			"joins by time and technique. Running it now would measure "+
			"nothing while claiming to measure their pipeline, so it is "+
			"refused rather than half-run. Reference mode — the default — "+
			"measures what this program's own pack caught on the stream, as "+
			"the calibrated instrument; their-Sigma mode measures their own "+
			"rules under this engine", ModeTheirAlert)
	default:
		return nil, fmt.Errorf("%q is not a scoring mode; the closed set is "+
			"%s and %s:DIR (this build), and %s:FILE (phase 2)", mode,
			ModeReference, ModeTheirSigma, ModeTheirAlert)
	}

	ref := opts.Reference
	shipped := ref == nil
	if shipped {
		loaded, err := LoadReference()
		if err != nil {
			return nil, err
		}
		ref = loaded
	}
	// The caller's own pack, not the shipped one the run just loaded on
	// its own behalf: naming a reference directory and their Sigma rules
	// in one run asks for two instruments, and a scorecard that mixed
	// them would name neither.
	if opts.Reference != nil && theirs != nil {
		return nil, fmt.Errorf("two instruments were named: a reference " +
			"pack and their Sigma rules. One run scores one instrument, " +
			"and a scorecard that mixed them would name neither")
	}
	if theirs != nil {
		// Their library is the instrument: replayed by the same passes,
		// ambient-calibrated the same way, and — because it shares none
		// of the pack's ids — joined to the corpus at technique level by
		// the scorer below. The corpus loads loose (shape checks only):
		// its pack-id expectations belong to reference mode, and holding
		// their rules to the shipped pack's ids would refuse every
		// scenario before anything ran.
		ref = theirs.ref
		shipped = false
	}
	corpus, err := loadCorpus(ref, shipped)
	if err != nil {
		return nil, err
	}
	var selected []*Loaded
	if len(opts.Scenarios) == 0 {
		selected = corpus
	} else {
		for _, id := range opts.Scenarios {
			l := ByID(corpus, id)
			if l == nil {
				return nil, fmt.Errorf("there is no scenario called %q in the "+
					"seed corpus; windtunnel list-scenarios names what ships",
					id)
			}
			selected = append(selected, l)
		}
	}

	baseName, base := FixtureName, DefaultBase()
	if opts.Base != "" {
		base, err = ReadBase(opts.Base)
		if err != nil {
			return nil, fmt.Errorf("reading the base stream: %w", err)
		}
		baseName = filepath.Base(opts.Base)
	}
	baseDigest, baseEvents := BaseDigest(base)

	into := opts.Into
	if into == "" {
		into, err = os.MkdirTemp("", "windtunnel-")
		if err != nil {
			return nil, err
		}
	} else if err := os.MkdirAll(into, 0o700); err != nil {
		return nil, err
	}

	// The ambient pass: the same rules over the base stream alone. Any alert
	// it raises is the estate's, not the scenario's, and every join below
	// subtracts it before crediting the scenario with anything — the
	// calibration statement, made arithmetic.
	ambientSp, err := WriteScratch(filepath.Join(into, "ambient"), base)
	if err != nil {
		return nil, err
	}
	ambientBudget := latenessHistogram(base).quantile(0.99)
	ambient, err := runPass(ambientSp, ref, ambientBudget)
	if err != nil {
		return nil, fmt.Errorf("the ambient pass: %w", err)
	}
	ambientSp.Close()

	card := &Scorecard{Schema: DocSchema, Mode: PhaseReplay, Engine: Engine,
		ScoreMode: mode, Standing: standingOf(mode),
		Base: baseName, BaseDigest: baseDigest,
		BaseEvents: baseEvents, Pack: ref.Name, PackDigest: ref.Digest,
		Corpus: CorpusName, Seed: opts.Seed, Scratch: into,
		GeneratedAt: opts.Now.UTC(),
		Caveat:      attributionCaveat}
	// The ambient count is sealed on the document so a diff between two
	// scorecards can tell a rules finding from an estate finding: what the
	// instrument raised on the base stream alone, before any session was
	// spliced into it.
	for _, n := range ambient.loud {
		card.AmbientFires += n
	}
	for _, hits := range ambient.hits {
		card.AmbientFires += len(hits)
	}
	if theirs != nil {
		card.TheirSigma = theirs.report
		card.ModeBlind = sigmaJoinBlind
	}
	if opts.Mutate > 0 {
		card.Mutation = &MutationReport{Requested: opts.Mutate,
			Caveat: mutationCaveat}
	}
	for _, l := range selected {
		row, mrow, err := runOne(l, ref, base, into, opts.Seed, ambient,
			theirs != nil, opts.Mutate)
		if err != nil {
			return nil, err
		}
		if mrow != nil {
			card.Mutation.Rows = append(card.Mutation.Rows, *mrow)
		}
		card.Rows = append(card.Rows, *row)
		card.Scenarios = append(card.Scenarios, ScenarioDigest{
			ID: l.Scenario.ID, Digest: l.Digest, Twin: l.Scenario.Twin.ID})
		card.Blinds = append(card.Blinds, Blind{Scenario: l.Scenario.ID,
			Blind: l.Scenario.Blind})
	}
	if err := card.aggregate(); err != nil {
		return nil, err
	}
	if card.Mutation != nil {
		card.Mutation.tally()
	}
	if err := card.seal(); err != nil {
		return nil, err
	}
	if opts.Signer != nil {
		sig, serr := SignScorecard(card, opts.Signer)
		if serr != nil {
			return nil, serr
		}
		card.Signature = &sig
	}
	return card, nil
}

// replaySession splices one placed session into the base stream, writes
// the result to a scratch spool at dir, and replays the instrument over it
// with the watermark budget the spliced stream's own arrivals earn.
func replaySession(base, events []telemetry.Event, ref *Reference,
	dir string) (*passResult, error) {

	stream := Interleave(base, events)
	sp, err := WriteScratch(dir, stream)
	if err != nil {
		return nil, err
	}
	defer sp.Close()
	return runPass(sp, ref, latenessHistogram(stream).quantile(0.99))
}

// referenceRows joins every expectation a scenario declares to a replay,
// by id.
func referenceRows(sc *Scenario, ref *Reference, attack,
	ambient *passResult, placed *Placed) []ExpectRow {

	var rows []ExpectRow
	for _, x := range sc.Expects {
		rows = append(rows, *scoreExpect(sc, x, ref, attack, ambient, placed))
	}
	return rows
}

// sessionOutcome is the tier one replayed session lands in, by the join
// the instrument calls for — the same fold for the scenario's own session
// and for every variant of it, so a variant is scored as the original was.
func sessionOutcome(sc *Scenario, ref *Reference, attack,
	ambient *passResult, placed *Placed, their bool) string {

	if their {
		return theirOutcome(joinByTechnique(sc, ref, attack, ambient))
	}
	return outcomeOf(referenceRows(sc, ref, attack, ambient, placed))
}

// runOne runs one scenario and its twin over the base stream and scores
// both — by the id join in reference mode, by the technique join when the
// instrument is their Sigma rules — and, when mutate is above zero, that
// many respellings of the scenario's session as well.
func runOne(l *Loaded, ref *Reference, base []telemetry.Event, into string,
	seed int64, ambient *passResult, their bool, mutate int) (*Row,
	*MutationRow, error) {

	sc := l.Scenario
	if err := Preflight(sc, base); err != nil {
		return nil, nil, err
	}
	anchor, err := DefaultAnchor(base)
	if err != nil {
		return nil, nil, err
	}

	pass := func(steps []Step, suffix string) (*passResult, *Placed, error) {
		placed, perr := Place(sc, steps, base, seed, anchor)
		if perr != nil {
			return nil, nil, perr
		}
		res, rerr := replaySession(base, placed.Events, ref,
			filepath.Join(into, sanitize(sc.ID)+suffix))
		if rerr != nil {
			return nil, nil, rerr
		}
		return res, placed, nil
	}

	attack, placed, err := pass(sc.Steps, "")
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", sc.ID, err)
	}
	twinPass, twinPlaced, err := pass(sc.Twin.Steps, "--twin")
	if err != nil {
		return nil, nil, fmt.Errorf("%s, its twin: %w", sc.ID, err)
	}

	row := &Row{Scenario: sc.ID, Digest: l.Digest, Family: sc.Family,
		Techniques: sc.Technique, SessionEvents: len(placed.Events),
		Twin: TwinOutcome{ID: sc.Twin.ID, Outcome: TwinQuiet}}
	if their {
		// The technique join: one must-alert per rule of theirs that tags
		// a technique this scenario stages, met when that rule fired
		// above ambient. A rule can intersect and still not fire — those
		// are the misses the mode reports in these rows, not hides; a
		// scenario nothing of theirs even tags is the plain miss its note
		// says it is.
		row.Expects = joinByTechnique(sc, ref, attack, ambient)
		row.Note = theirRowNote(sc, ref, attack, ambient, row.Expects)
		row.Outcome = theirOutcome(row.Expects)
	} else {
		row.Expects = referenceRows(sc, ref, attack, ambient, placed)
		row.Outcome = outcomeOf(row.Expects)
	}

	// The twin: any new alert is a false fire — the precision axis.
	twinFired := false
	for id, n := range twinPass.loud {
		if n > ambient.loud[id] {
			twinFired = true
		}
	}
	for id, hits := range twinPass.hits {
		if len(hits) > len(ambient.hits[id]) {
			twinFired = true
		}
	}
	if twinFired {
		row.Twin.Outcome = TwinFalseFire
	}
	row.Twin.SessionEvents = len(twinPlaced.Events)
	if mutate == 0 {
		return row, nil, nil
	}
	mrow, err := runVariants(l, ref, base, into, placed, ambient, their,
		row.Outcome, mutate)
	if err != nil {
		return nil, nil, err
	}
	return row, mrow, nil
}

// scoreExpect joins one expectation to what the replay found. The join is
// by id — the highest-fidelity join there is, because the scenario and the
// pack share the vocabulary — and every count is the count above ambient.
func scoreExpect(sc *Scenario, x Expect, ref *Reference, attack,
	ambient *passResult, placed *Placed) *ExpectRow {

	r := &ExpectRow{Kind: x.Kind, ID: x.ID, Verdict: x.Verdict}
	newLoud := func(id string) int { return attack.loud[id] - ambient.loud[id] }
	newHits := func(id string) int {
		return len(attack.hits[id]) - len(ambient.hits[id])
	}
	switch x.Kind {
	case ExpectRule:
		if !ref.has(x.Kind, x.ID) {
			// The honesty rule: a rule the pack no longer carries is a miss
			// the scorecard reports, never an error that stops the run. The
			// build-time corpus validation catches the drift for the shipped
			// corpus; a third-party pack scored here gets the truth instead
			// of a refusal. The one verdict this must not satisfy is
			// stays-quiet — a deleted rule cannot fire, and letting its
			// absence count as quiet would mean deleting rules improves a
			// scorecard.
			r.Met = false
			if x.Verdict == VerdictStaysQuiet {
				r.Note = "the rule is not in the reference pack, so nothing " +
					"proves the session stayed quiet — a rule cannot fire " +
					"from outside the pack, and deleting one must not " +
					"improve a scorecard"
			} else {
				r.Note = "the rule is not in the reference pack: deleted or " +
					"renamed since the scenario was written, and nothing it " +
					"could have caught was caught"
			}
			return r
		}
		switch x.Verdict {
		case VerdictMustAlert:
			r.Fires = newLoud(x.ID)
			r.Met = r.Fires > 0
			if r.Met {
				r.AttributionSecs = 0
			}
		case VerdictFiresQuietly:
			r.Fires = attack.quiet[x.ID] - ambient.quiet[x.ID]
			r.Met = r.Fires > 0
		case VerdictStaysQuiet:
			r.Fires = newLoud(x.ID)
			r.Met = r.Fires == 0
		}
	case ExpectCorrelation:
		if !ref.has(x.Kind, x.ID) {
			r.Met = false
			if x.Verdict == VerdictStaysQuiet {
				r.Note = "the correlation is not in the reference pack, so " +
					"nothing proves the session stayed quiet — deleting the " +
					"window must not improve a scorecard"
			} else {
				r.Note = "the correlation is not in the reference pack: " +
					"deleted or renamed since the scenario was written, and " +
					"the window it would have closed never opened"
			}
			return r
		}
		r.Fires = newHits(x.ID)
		switch x.Verdict {
		case VerdictMustAlert:
			r.Met = r.Fires > 0
			if r.Met {
				r.AttributionSecs = attributionSecs(x.ID, ref, attack,
					ambient, placed)
			} else if late := attack.late[x.ID] - ambient.late[x.ID]; late > 0 {
				// The two-clock edge, told apart by name: the window closed
				// before the completing event arrived, which is a finding
				// about the lateness budget, not about the content.
				r.MissKind = MissLateness
				r.Note = fmt.Sprintf("%d event(s) of this session arrived "+
					"after their window had closed under the stream's own "+
					"watermark: a lateness miss, not a content miss", late)
			} else {
				r.MissKind = MissContent
			}
		case VerdictStaysQuiet:
			r.Met = r.Fires == 0
		}
	}
	return r
}

// outcomeOf folds a scenario's expectation rows into its categorical tier.
func outcomeOf(expects []ExpectRow) string {
	var unmetMust, unmetStay bool
	for _, x := range expects {
		if x.Met {
			continue
		}
		switch x.Verdict {
		case VerdictMustAlert:
			unmetMust = true
		case VerdictStaysQuiet:
			unmetStay = true
		}
	}
	switch {
	case unmetMust:
		return OutcomeMissed
	case unmetStay:
		return OutcomeWronglyQuiet
	}
	for _, x := range expects {
		if x.Verdict == VerdictMustAlert && x.Met {
			return OutcomeCaughtAlert
		}
	}
	return OutcomeCaughtTelemetry
}

// attributionSecs is the event-time-to-attribution for a met correlation:
// the gap between the step that completed the pattern and the window that
// attributed it (decision 9). A property of the rule's own windows — never
// of anybody's shifts, and the document says so in its caveat.
func attributionSecs(corrID string, ref *Reference, attack,
	ambient *passResult, placed *Placed) float64 {

	var rule *correlate.Rule
	for i := range ref.Corrs {
		if strings.EqualFold(ref.Corrs[i].ID, corrID) {
			rule = &ref.Corrs[i]
			break
		}
	}
	if rule == nil || len(placed.Events) == 0 {
		return 0
	}
	hits := attack.hits[corrID]
	if len(hits) <= len(ambient.hits[corrID]) {
		return 0
	}
	hit := hits[len(ambient.hits[corrID])]
	// The completing event: the session's last event, inside the hit's
	// window, that matched the correlation's last rule — the one whose
	// arrival the window was waiting on.
	want := rule.Rules[len(rule.Rules)-1]
	var completing *telemetry.Event
	for i := range placed.Events {
		e := placed.Events[i]
		if e.Time.Before(hit.From) || !e.Time.Before(hit.To) {
			continue
		}
		for _, m := range attack.matched[e.Received] {
			if strings.EqualFold(m, want) {
				completing = &placed.Events[i]
			}
		}
	}
	if completing == nil {
		return 0
	}
	d := hit.To.Sub(completing.Time).Seconds()
	if d < 0 {
		d = 0
	}
	return d
}

// sanitize makes a scenario id safe as one path element.
func sanitize(id string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			return r
		}
		return '-'
	}, id)
}

// sortRows orders the scorecard's rows by scenario id, so two documents
// diff as tables rather than as maps.
func sortRows(rows []Row) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Scenario < rows[j].Scenario })
}
