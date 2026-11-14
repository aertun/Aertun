// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// The scenario: a malicious agent session as the SOC would see it, declared
// as data (decision 1).
//
// The shape borrows from the formalisms that earned it and refuses the rest.
// From Atomic Red Team: typed bindings with defaults and a prereq split —
// preflight checks the base stream can host the session before anything is
// spliced, and a failed preflight refuses the run rather than splicing an
// event no rule can read. From Caldera: the fact system's shape — a step may
// bind a generated value later steps reference, giving one coherent session
// rather than independent events — implemented as a closed substitution
// table, not a parser over command strings. From Sigma: the discipline that
// a scenario, like a rule, describes what to look for and never what to do,
// and `falsepositives` as a first-class field, which is what the benign twin
// is. The executor — Atomic's shell, Caldera's command — is refused entirely:
// the attack is the shape of the log.

// ScenarioSchema is the scenario format this build reads. A file from another
// schema is refused rather than best-effort loaded, for the same reason as
// every versioned schema here: fields change meaning between versions.
const ScenarioSchema = 1

// The eight scenario families. A closed set (decision: closed sets
// everywhere), each anchored in the repo's own failure catalogue and the
// public agent-threat literature. Delegation-abuse is phase 2 by decision:
// its telemetry fields need the ingest side first.
const (
	FamilyToolPoisoning = "tool-poisoning"
	FamilyConfigRugPull = "config-rug-pull"
	FamilyTrifecta      = "trifecta"
	FamilySlopsquat     = "slopsquat"
	FamilyRecorderBlind = "recorder-blind"
	FamilyInjection     = "injection-hijack"
	FamilyDelegation    = "delegation-abuse"
	FamilyCostBomb      = "cost-bomb"
)

// Families is every family, in the order the research document numbers them.
func Families() []string {
	return []string{FamilyToolPoisoning, FamilyConfigRugPull, FamilyTrifecta,
		FamilySlopsquat, FamilyRecorderBlind, FamilyInjection,
		FamilyDelegation, FamilyCostBomb}
}

func familyKnown(f string) bool {
	for _, k := range Families() {
		if k == f {
			return true
		}
	}
	return false
}

// The three safety classes. Phase 1 ships only synthetic-only; the other two
// exist in the vocabulary so phase 3's containment work does not have to
// invent words, and are refused here with the reason.
const (
	SafetySynthetic = "synthetic-only"
	SafetyCanary    = "canary-targeted"
	SafetyLive      = "live-contained"
)

// SafetyClasses is the closed set.
func SafetyClasses() []string {
	return []string{SafetySynthetic, SafetyCanary, SafetyLive}
}

func safetyKnown(s string) bool {
	for _, k := range SafetyClasses() {
		if k == s {
			return true
		}
	}
	return false
}

// The two phases. Phase 1 accepts only replay: a live phase is a containment
// design (phase 3), and accepting the word early would be the one field here
// that promised more than the code does.
const (
	PhaseReplay = "replay"
	PhaseLive   = "live"
)

// Lateness sources, another closed set. "measured" derives arrival delay from
// the base stream's own histogram; the profiles cover fixture corpora that
// carry no arrival history of their own.
const (
	LatenessMeasured     = "measured"
	ProfileCloudAudit    = "profile:cloud-audit"
	ProfileLocalAgent    = "profile:local-agent"
	defaultLateness      = LatenessMeasured
	latenessFieldDefault = ""
)

// LatenessSources is the closed set a scenario may name.
func LatenessSources() []string {
	return []string{LatenessMeasured, ProfileCloudAudit, ProfileLocalAgent}
}

func latenessKnown(s string) bool {
	for _, k := range LatenessSources() {
		if k == s {
			return true
		}
	}
	return false
}

// The expect kinds and verdicts. Expects use the pack's own ids in reference
// mode — the highest-fidelity join, because the ids are shared — and the
// verdicts are the closed set the scorer answers in.
const (
	ExpectRule        = "rule"
	ExpectCorrelation = "correlation"

	VerdictMustAlert    = "must-alert"    // a named detection must alert
	VerdictFiresQuietly = "fires-quietly" // a quiet leg must be counted
	VerdictStaysQuiet   = "stays-quiet"   // this must NOT fire on this session
)

// Techniques is the closed technique vocabulary a scenario may cite: the
// ATLAS, OWASP ASI and ATT&CK ids the reference pack's own rules carry, plus
// the ids the corpus needs that no rule carries yet (reported as the gap they
// are). "provenance: various is a field nobody can audit" — a technique id
// nobody recognises is the same shape of nobody-can-audit.
var Techniques = []string{
	"AML.T0010", "AML.T0051", "AML.T0051.001",
	"ASI01", "ASI02", "ASI03", "ASI04", "ASI06", "ASI07", "ASI08", "ASI10",
	"T1041", "T1070.001", "T1098", "T1195.002", "T1213", "T1550", "T1567",
	"LLM10",
}

func techniqueKnown(t string) bool {
	for _, k := range Techniques {
		if k == t {
			return true
		}
	}
	return false
}

// The preflight checks, a closed set. Each is Atomic's prereq half: prove the
// base stream can host the session before splicing anything into it.
const (
	// CheckSourceEmits refuses when the base stream carries no event from the
	// named source: the scenario's events hide among real traffic, and a
	// source nobody emits means no rule that reads it can be asked anything.
	CheckSourceEmits = "source-emits"
	// CheckToolLabelled refuses when the base stream has never carried the
	// named tool with the named label: the label is a declaration made at the
	// ingest boundary, and splicing labelled events into a stream whose
	// boundary never stamped that label would test a world this stream is not.
	CheckToolLabelled = "tool-labelled"
)

// PreflightChecks is the closed set.
func PreflightChecks() []string {
	return []string{CheckSourceEmits, CheckToolLabelled}
}

func preflightKnown(c string) bool {
	for _, k := range PreflightChecks() {
		if k == c {
			return true
		}
	}
	return false
}

// Binding is one substitution variable: a generated value or a literal.
// Generated bindings are seeded and deterministic — the same session identity
// every run, which is what makes a scenario's digest worth recording and its
// trace ids joinable. Literal bindings exist for destinations, and only
// canary-shaped ones are accepted: a literal destination an attacker chose is
// a live target wearing a data file.
type Binding struct {
	Gen   string `json:"gen,omitempty"`
	Seed  int64  `json:"seed,omitempty"`
	Value string `json:"value,omitempty"`
}

// Step is one event of the session, at an event-time offset from the session
// anchor. No Time and no Received: the splicer owns both clocks (decision 3),
// and a scenario that carried either would be claiming a delivery moment no
// recording can vouch for.
type Step struct {
	Name string `json:"name"`
	// At is seconds from the session anchor.
	At int `json:"at"`
	// Repeat expands the step into Count copies, Every seconds apart — the
	// declarative form of a loop, without which a cost bomb would be a
	// hundred and thirty hand-written entries nobody could review as a diff.
	// Data, still: it names events, never behaviour.
	Repeat *Repeat         `json:"repeat,omitempty"`
	Emit   telemetry.Event `json:"emit"`
}

// Repeat is a step's expansion rule.
type Repeat struct {
	Count int `json:"count"`
	// Every is seconds between copies.
	Every int `json:"every"`
}

// Expect is what the reference stack should see. The join is by the pack's
// own ids — one field, two resolutions later (technique ids in
// their-controls mode, phase 2).
type Expect struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Verdict string `json:"verdict"`
}

// PreflightCheck is one check the base stream must pass before the run.
type PreflightCheck struct {
	Check  string `json:"check"`
	Source string `json:"source,omitempty"`
	Tool   string `json:"tool,omitempty"`
	Label  string `json:"label,omitempty"`
}

// Twin is the benign twin: the same event shape doing the legitimate version
// of the work (decision 2). Nothing may alert on it — not the loud rules, not
// the correlations — and a run says so per scenario. Sigma carries
// falsepositives as a first-class field; this is that, executable.
type Twin struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Narrative string `json:"narrative"`
	Steps     []Step `json:"steps"`
}

// Scenario is one scripted malicious session with its twin, its expectations
// and its declared blind spot.
type Scenario struct {
	Schema int    `json:"schema"`
	ID     string `json:"id"`
	Title  string `json:"title"`
	Family string `json:"family"`
	Phase  string `json:"phase"`
	Safety string `json:"safety"`
	// Narrative is one sentence a founder can read — the pack's title style.
	Narrative string             `json:"narrative"`
	Catalogue string             `json:"catalogue"`
	Technique []string           `json:"technique"`
	Bindings  map[string]Binding `json:"bindings"`
	Steps     []Step             `json:"steps"`
	Expects   []Expect           `json:"expects"`
	Twin      Twin               `json:"benign-twin"`
	Preflight []PreflightCheck   `json:"preflight"`
	// Blind is what this scenario deliberately cannot test. Mandatory, in the
	// pack's own tradition: a scenario that claims total coverage is the
	// vendor the scorecard exists to prevent.
	Blind    string `json:"blind"`
	Lateness string `json:"lateness,omitempty"`
}

// IDs is what expects are resolved against: the reference pack's rule ids
// (with whether each is quiet) and correlation ids. A struct rather than the
// loaded pack so validation stays a question about ids, not about files.
type IDs struct {
	Rules        map[string]bool
	Correlations map[string]bool
}

// bindingName is the shape a substitution variable's name must take.
var bindingName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// placeholder finds every ${name} a string carries.
var placeholder = regexp.MustCompile(`\$\{([a-z][a-z0-9-]*)\}`)

// Validate refuses a scenario that cannot do what it claims. Every refusal
// names its reason; the closed sets are listed in the messages so an author
// is told what exists rather than only that they are wrong.
//
// ids may be nil to check everything that does not need the pack — the shape
// checks — which is what a third-party file gets before anyone resolves its
// expectations.
func (sc *Scenario) Validate(ids *IDs) error {
	if sc.Schema != ScenarioSchema {
		return fmt.Errorf("%s: the schema is %d and this build reads %d", sc.ID,
			sc.Schema, ScenarioSchema)
	}
	if strings.TrimSpace(sc.ID) == "" {
		return fmt.Errorf("a scenario needs an id, so a scorecard row can say " +
			"which session it was")
	}
	if strings.TrimSpace(sc.Title) == "" {
		return fmt.Errorf("%s has no title; a row naming only an id is one "+
			"nobody can read at three in the morning", sc.ID)
	}
	if strings.TrimSpace(sc.Narrative) == "" {
		return fmt.Errorf("%s has no one-sentence narrative. The pack's titles "+
			"carry the argument; a scenario without one is a list of events",
			sc.ID)
	}
	if !familyKnown(sc.Family) {
		return fmt.Errorf("%s is in the family %q; the closed set is %s",
			sc.ID, sc.Family, strings.Join(Families(), ", "))
	}
	if sc.Phase != PhaseReplay {
		return fmt.Errorf("%s declares phase %q. This build is replay-only: a "+
			"live phase arrives with phase 3's containment, and accepting the "+
			"word before the containment would be the one field here that "+
			"promised more than the code does", sc.ID, sc.Phase)
	}
	if !safetyKnown(sc.Safety) {
		return fmt.Errorf("%s declares safety %q; the closed set is %s", sc.ID,
			sc.Safety, strings.Join(SafetyClasses(), ", "))
	}
	if sc.Safety != SafetySynthetic {
		return fmt.Errorf("%s declares safety %q, which belongs to a live "+
			"phase this build refuses. Replay is safe by construction; the "+
			"other safety classes arrive with phase 3", sc.ID, sc.Safety)
	}
	if len(sc.Technique) == 0 {
		return fmt.Errorf("%s cites no technique. The coverage grid is keyed "+
			"on these, and a scenario with none files itself under nothing",
			sc.ID)
	}
	for _, t := range sc.Technique {
		if !techniqueKnown(t) {
			return fmt.Errorf("%s cites %q, which is not in the technique "+
				"vocabulary. The closed set is what the reference pack's own "+
				"rules carry plus the gaps the corpus reports as gaps", sc.ID, t)
		}
	}
	if sc.Lateness != latenessFieldDefault && !latenessKnown(sc.Lateness) {
		return fmt.Errorf("%s asks for lateness %q; the closed set is %s",
			sc.ID, sc.Lateness, strings.Join(LatenessSources(), ", "))
	}
	if strings.TrimSpace(sc.Blind) == "" {
		return fmt.Errorf("%s declares no blind spot. A scenario that claims "+
			"total coverage is the vendor the scorecard exists to prevent, "+
			"and the field is where the honesty is written down", sc.ID)
	}

	// The binding table: a closed set of names, each a generator from the
	// closed set or a canary literal.
	if len(sc.Bindings) == 0 {
		return fmt.Errorf("%s binds nothing, so every step emits the same "+
			"fixed strings and no run is a session", sc.ID)
	}
	for name, b := range sc.Bindings {
		if !bindingName.MatchString(name) {
			return fmt.Errorf("%s binds %q, which is not a binding name a "+
				"step could reference", sc.ID, name)
		}
		switch name {
		case "agent", "trace":
			// Generated only. A literal agent or trace id is somebody else's
			// session wearing this scenario's steps, and the collision is
			// exactly what the seeded disjoint ranges exist to avoid.
			if b.Value != "" {
				return fmt.Errorf("%s gives %q the literal %q. Agent and "+
					"trace identities are generated — a literal would be "+
					"somebody else's session, and preflight would refuse the "+
					"collision anyway", sc.ID, name, b.Value)
			}
			if b.Gen == "" {
				return fmt.Errorf("%s binds %q with neither a generator nor a "+
					"value", sc.ID, name)
			}
		case "dest":
			if b.Value == "" && b.Gen == "" {
				return fmt.Errorf("%s binds dest with neither a generator nor "+
					"a value", sc.ID)
			}
			if b.Value != "" {
				if err := canary(b.Value); err != nil {
					return fmt.Errorf("%s: %w", sc.ID, err)
				}
			}
		default:
			return fmt.Errorf("%s binds %q. The substitution table is closed "+
				"— agent, trace, dest — because an open one is a template "+
				"language, and a template language is where an interpreter "+
				"grows", sc.ID, name)
		}
		if b.Gen != "" && !genKnown(b.Gen) {
			return fmt.Errorf("%s binds %q with the generator %q; the closed "+
				"set is %s", sc.ID, name, b.Gen, strings.Join(Gens(), ", "))
		}
	}

	// The steps and the twin's steps: same rules, both directions of the
	// fixture.
	if err := validateSteps(sc.ID, "step", sc.Steps, sc.Bindings); err != nil {
		return err
	}
	if err := validateSteps(sc.ID, "twin step", sc.Twin.Steps, sc.Bindings); err != nil {
		return err
	}
	if strings.TrimSpace(sc.Twin.ID) == "" {
		return fmt.Errorf("%s ships no benign twin. A scenario without one "+
			"measures nothing about precision — the same discipline that "+
			"refuses a rule with no fixture it refuses — and it is refused "+
			"here, not warned about", sc.ID)
	}
	if strings.TrimSpace(sc.Twin.Title) == "" {
		return fmt.Errorf("%s: the benign twin %s has no title", sc.ID,
			sc.Twin.ID)
	}
	if len(sc.Twin.Steps) == 0 {
		return fmt.Errorf("%s: the benign twin %s has no steps. An empty twin "+
			"trivially stays quiet, which is the same as no twin", sc.ID,
			sc.Twin.ID)
	}

	// The preflight checks.
	for i, p := range sc.Preflight {
		if !preflightKnown(p.Check) {
			return fmt.Errorf("%s: preflight %d is %q; the closed set is %s",
				sc.ID, i+1, p.Check, strings.Join(PreflightChecks(), ", "))
		}
		switch p.Check {
		case CheckSourceEmits:
			if strings.TrimSpace(p.Source) == "" {
				return fmt.Errorf("%s: preflight %d checks a source and names "+
					"none", sc.ID, i+1)
			}
		case CheckToolLabelled:
			if strings.TrimSpace(p.Tool) == "" ||
				strings.TrimSpace(p.Label) == "" {
				return fmt.Errorf("%s: preflight %d checks a tool's label and "+
					"names the tool, the label or the source it fails to", sc.ID, i+1)
			}
		}
	}

	// The expectations.
	if len(sc.Expects) == 0 {
		return fmt.Errorf("%s expects nothing, so no run of it can be scored",
			sc.ID)
	}
	seen := map[string]bool{}
	for i, x := range sc.Expects {
		switch x.Kind {
		case ExpectRule, ExpectCorrelation:
		default:
			return fmt.Errorf("%s: expect %d is of kind %q; the closed set is "+
				"%s, %s", sc.ID, i+1, x.Kind, ExpectRule, ExpectCorrelation)
		}
		switch x.Verdict {
		case VerdictMustAlert, VerdictFiresQuietly, VerdictStaysQuiet:
		default:
			return fmt.Errorf("%s: expect %d wants %q; the closed set is %s",
				sc.ID, i+1, x.Verdict, strings.Join([]string{
					VerdictMustAlert, VerdictFiresQuietly, VerdictStaysQuiet},
					", "))
		}
		if strings.TrimSpace(x.ID) == "" {
			return fmt.Errorf("%s: expect %d names no id", sc.ID, i+1)
		}
		if x.Kind == ExpectCorrelation && x.Verdict == VerdictFiresQuietly {
			return fmt.Errorf("%s: expect %d wants the correlation %s to fire "+
				"quietly, and a correlation is not quiet — it exists to "+
				"raise, and its legs are the quiet half", sc.ID, i+1, x.ID)
		}
		key := x.Kind + " " + x.ID
		if seen[key] {
			return fmt.Errorf("%s: two expects name %s", sc.ID, key)
		}
		seen[key] = true
	}
	if ids != nil {
		for i, x := range sc.Expects {
			switch x.Kind {
			case ExpectRule:
				quiet, ok := ids.Rules[strings.ToLower(x.ID)]
				if !ok {
					return fmt.Errorf("%s: expect %d names the rule %q and no "+
						"rule called that is in the reference pack. An "+
						"expectation nothing can satisfy is a rule fixture "+
						"that names a field nothing emits", sc.ID, i+1, x.ID)
				}
				if x.Verdict == VerdictFiresQuietly && !quiet {
					return fmt.Errorf("%s: expect %d wants %q to fire quietly "+
						"and that rule is loud — it raises on its own, and "+
						"calling its firing quiet would mislabel every hit",
						sc.ID, i+1, x.ID)
				}
			case ExpectCorrelation:
				if _, ok := ids.Correlations[strings.ToLower(x.ID)]; !ok {
					return fmt.Errorf("%s: expect %d names the correlation %q "+
						"and no correlation called that is in the reference "+
						"pack", sc.ID, i+1, x.ID)
				}
			}
		}
	}
	return nil
}

// validateSteps checks one session's steps: names unique, offsets ordered,
// every event well-formed apart from the two clocks the splicer owns, and
// every placeholder bound.
func validateSteps(id, what string, steps []Step, bindings map[string]Binding) error {
	if len(steps) == 0 {
		return fmt.Errorf("%s has no %ss, so there is no session to splice",
			id, what)
	}
	names := map[string]bool{}
	prev := -1
	for i, s := range steps {
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("%s: %s %d has no name", id, what, i+1)
		}
		if names[s.Name] {
			return fmt.Errorf("%s: two %ss are called %q", id, what, s.Name)
		}
		names[s.Name] = true
		if s.At < 0 {
			return fmt.Errorf("%s: %s %q sits before the session anchor, and "+
				"a session is a sequence, not a scatter", id, what, s.Name)
		}
		if s.At <= prev {
			return fmt.Errorf("%s: %s %q does not follow %q in event time. "+
				"The order is the attack; a scenario that shuffles its steps "+
				"would be a different one each run", id, what, s.Name,
				steps[i-1].Name)
		}
		prev = s.At
		if s.Repeat != nil {
			if s.Repeat.Count < 1 || s.Repeat.Count > 1000 {
				return fmt.Errorf("%s: %s %q repeats %d time(s); a repeat is "+
					"between 1 and 1000, and beyond that the file is a "+
					"directory", id, what, s.Name, s.Repeat.Count)
			}
			if s.Repeat.Every < 0 {
				return fmt.Errorf("%s: %s %q repeats every %d seconds, and a "+
					"loop cannot run backwards", id, what, s.Name,
					s.Repeat.Every)
			}
		}
		if err := validateEmit(id, what, s.Name, s.Emit, bindings); err != nil {
			return err
		}
	}
	return nil
}

// validateEmit checks one emitted event. It is telemetry.Validate's checks
// minus the two clocks — a scenario must not own Time or Received (decision
// 3) — plus the placeholder resolution: a ${name} that names no binding is
// the scenario equivalent of a rule reading a field nothing emits.
func validateEmit(id, what, name string, e telemetry.Event, bindings map[string]Binding) error {
	if !e.Time.IsZero() || !e.Received.IsZero() {
		return fmt.Errorf("%s: %s %q carries its own clocks. The splicer owns "+
			"both — the victim's windows are cut on event time and closed on "+
			"arrival, and a scenario that fixed either would be scoring a "+
			"delivery no recording can vouch for", id, what, name)
	}
	if strings.TrimSpace(e.Source) == "" {
		return fmt.Errorf("%s: %s %q emits into no source. Detections are "+
			"written against the source, and an event that arrives "+
			"anonymously cannot be matched by any of them", id, what, name)
	}
	if !e.Class.Valid() {
		return fmt.Errorf("%s: %s %q emits class %d, which is not a class. "+
			"The value is category*1000 + index", id, what, name, e.Class)
	}
	for _, idn := range []struct {
		what string
		id   telemetry.ID
	}{{"actor", e.Actor}, {"target", e.Target}, {"device", e.Device}} {
		if idn.id.Zero() {
			continue
		}
		if strings.TrimSpace(idn.id.Issuer) == "" ||
			strings.TrimSpace(idn.id.Value) == "" {
			return fmt.Errorf("%s: %s %q carries a %s without both its issuer "+
				"and its value, and half an identifier joins nothing", id,
				what, name, idn.what)
		}
	}
	for _, v := range emitStrings(e) {
		for _, m := range placeholder.FindAllStringSubmatch(v, -1) {
			if _, ok := bindings[m[1]]; !ok {
				return fmt.Errorf("%s: %s %q references ${%s} and the binding "+
					"table does not carry it. The table is closed, and a "+
					"reference outside it is the scenario's version of a rule "+
					"that reads a field nothing emits", id, what, name, m[1])
			}
		}
	}
	return nil
}

// emitStrings is every string slot an emit carries, so placeholder checking
// and substitution walk the same list and cannot drift.
func emitStrings(e telemetry.Event) []string {
	out := []string{e.Message, e.Actor.Value, e.Actor.Issuer, e.Target.Value,
		e.Target.Issuer, e.Device.Value, e.Device.Issuer}
	for _, v := range e.Raw {
		out = append(out, v)
	}
	for _, o := range e.Observables {
		out = append(out, o.Value)
	}
	return out
}

// canary refuses a destination that is not canary-shaped: https, and a host
// under a reserved or internal suffix. A destination outside that shape is a
// live target wearing a data file, and the refusal is at validation time —
// the refusal-not-filter instinct every Validate here follows.
func canary(v string) error {
	u, err := url.Parse(v)
	if err != nil {
		return fmt.Errorf("the destination %q does not parse as a URL", v)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("the destination %q is not an http(s) URL, and an "+
			"egress step needs one to be a destination at all", v)
	}
	host := strings.ToLower(u.Hostname())
	for _, suffix := range []string{".example", ".internal", ".test", ".invalid"} {
		if strings.HasSuffix(host, suffix) {
			return nil
		}
	}
	return fmt.Errorf("the destination %q is not canary-shaped: the host must "+
		"end in .example, .internal, .test or .invalid. A scenario that could "+
		"name a real destination would be a live attack wearing a data file, "+
		"and replay's whole safety story is that it cannot", v)
}

// SortedBindingNames is the binding table's names, sorted — the one order a
// deterministic expansion can walk.
func (sc *Scenario) SortedBindingNames() []string {
	out := make([]string, 0, len(sc.Bindings))
	for k := range sc.Bindings {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// LatenessSource is the scenario's lateness choice, defaulting to measured.
func (sc *Scenario) LatenessSource() string {
	if sc.Lateness == latenessFieldDefault {
		return defaultLateness
	}
	return sc.Lateness
}

// span is the session's event-time span, the last step's offset expanded.
func (sc *Scenario) span() time.Duration {
	last := 0
	for _, s := range sc.Steps {
		at := s.At
		if s.Repeat != nil && s.Repeat.Count > 1 {
			at += s.Repeat.Every * (s.Repeat.Count - 1)
		}
		if at > last {
			last = at
		}
	}
	return time.Duration(last) * time.Second
}
