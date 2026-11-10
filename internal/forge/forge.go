// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package forge turns the AI analyst's past work into training episodes
// somebody else can rely on: what the model was shown, what it answered,
// and how a person ruled afterwards, in a file that is signed and whose
// Merkle root is kept in the audit log.
//
// # Why an episode holds no text
//
// The analyst reads two kinds of input: facts the program counted, and text
// somebody else wrote — a finding's title, the entity it names, the lines of
// evidence. Whoever is being detected can write that text. A training set
// that carried it would let them choose what the next model learns from,
// and a filter that tried to strip the dangerous parts would be a filter
// they get to test their text against.
//
// So nothing is filtered. An Episode has no field of type string. Every word
// in it is a value of a closed-set type whose only constructors return one
// of this package's own words, never the string they were handed; every
// identifier is a type whose only constructor accepts a string matching a
// strict pattern that prose cannot match — a register key, an audit entry
// hash, a model name; and every other field is a number, a boolean or a
// time. Text from the store has nowhere to go, because no field could hold
// it.
//
// # What makes a file trustworthy
//
// The file is JSON lines: one episode per line, in the order of the audit
// entries they come from, closed by a seal line. The seal holds how many
// episodes there are, the RFC 6962 Merkle root over their exact bytes, the
// tally of outcomes, and two signatures over all of that — Ed25519 and
// ML-DSA-65, by internal/pack's dual key, in this package's own context.
// Changing a line, moving one, dropping one or adding one changes the root
// or the count, and the file stops verifying; every line is also checked to
// be exactly the bytes this package would have written for what it says, so
// two files that say the same thing cannot differ. The exporter writes the
// root into the audit log too, so a file can be checked against the store's
// own record of what was exported, not only against a key.
//
// # Labels
//
// The label on an episode is what a person ruled, and the exporter reads
// only rulings a verified human recorded after the analyst's record. A model
// cannot record a ruling at all (internal/finding refuses one), and a
// service account's is a program's, not a judgement anybody stands behind.
//
// No training code lives in this repository. This package exports;
// whatever trains reads the file somewhere else.
package forge

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/translog"
)

const (
	// Context is the domain every seal's signatures are made in, and the
	// context of the key fingerprint a seal names. Versioned, so a change to
	// what is signed is a new context rather than a reinterpretation.
	Context = "aertun/forge/v1"
	// Format is the version of the episode a line holds.
	Format = 1
	// MaxEpisodes bounds one file. An episode line is well under a
	// kilobyte, so this keeps a file in the low hundreds of megabytes.
	MaxEpisodes = 200_000
	// MaxFile bounds a file read for verification, above the largest file
	// MaxEpisodes allows.
	MaxFile = 256 << 20
)

// ---- closed sets -----------------------------------------------------------

// closedSet is a list of words. Each set is its own type, so a word from one
// set cannot be used where another set's word belongs.
type closedSet interface{ words() []string }

// word is one word from the closed set S. Its only field is unexported, so
// outside this package a word cannot be made at all except by a
// constructor here — and every constructor returns an element of S's own
// list, never the string it was given.
type word[S closedSet] struct{ w string }

func (x word[S]) String() string { return x.w }

// IsZero reports that no word is set. encoding/json reads it for omitzero.
func (x word[S]) IsZero() bool { return x.w == "" }

// MarshalJSON refuses to write anything but a word of the set: the zero
// value has no word, and a required field left empty is a bug to stop at,
// not an empty string to export.
func (x word[S]) MarshalJSON() ([]byte, error) {
	if _, ok := lookup[S](x.w); !ok {
		return nil, errors.New("a required word is not set")
	}
	return json.Marshal(x.w)
}

// UnmarshalJSON accepts a word of the set and nothing else.
func (x *word[S]) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	got, ok := lookup[S](s)
	if !ok {
		// The rejected text is not repeated: it came from the file.
		return errors.New("a word outside its closed set")
	}
	*x = got
	return nil
}

// lookup returns the set's own copy of s, if s is in the set.
func lookup[S closedSet](s string) (word[S], bool) {
	var set S
	for _, w := range set.words() {
		if w == s {
			return word[S]{w: w}, true
		}
	}
	return word[S]{}, false
}

// must is lookup for this package's own words, which are in their sets by
// construction: a typo here stops the program at start-up.
func must[S closedSet](s string) word[S] {
	w, ok := lookup[S](s)
	if !ok {
		panic("forge: " + s + " is not in its own set")
	}
	return w
}

type verdicts struct{}

func (verdicts) words() []string { return []string{"real", "false-positive", "benign"} }

// Verdict is a triage verdict: the one the analyst suggested, or the one a
// person ruled. Real covers every ruling that says the finding was real —
// triaged, fixed or accepted — as the analyst's own counts do.
type Verdict = word[verdicts]

var (
	Real          = must[verdicts]("real")
	FalsePositive = must[verdicts]("false-positive")
	Benign        = must[verdicts]("benign")
)

// VerdictOf returns the verdict named s.
func VerdictOf(s string) (Verdict, bool) { return lookup[verdicts](s) }

type kinds struct{}

func (kinds) words() []string {
	return []string{"detection", "vulnerability", "control", "vendor", "code"}
}

// FindingKind is what raised a finding, from internal/finding's list.
type FindingKind = word[kinds]

// KindOf returns the finding kind named s.
func KindOf(s string) (FindingKind, bool) { return lookup[kinds](s) }

type severities struct{}

func (severities) words() []string { return []string{"low", "medium", "high", "critical"} }

// Severity is the word the analyst is shown for a finding's severity.
type Severity = word[severities]

// SeverityOf returns the severity named s.
func SeverityOf(s string) (Severity, bool) { return lookup[severities](s) }

type abstentions struct{}

func (abstentions) words() []string {
	return []string{"below-threshold", "counterfactual-unconfirmed", "no-usable-answer",
		"no-certified-gate"}
}

// Abstention is why the analyst offered no verdict.
type Abstention = word[abstentions]

var (
	// BelowThreshold: the model answered, under the confidence a
	// suggestion needs.
	BelowThreshold = must[abstentions]("below-threshold")
	// CounterfactualUnconfirmed: a closing verdict that did not hold when
	// the attacker-writable text was taken out of the question.
	CounterfactualUnconfirmed = must[abstentions]("counterfactual-unconfirmed")
	// NoUsableAnswer: nothing the model said was one of the three words,
	// or its samples tied.
	NoUsableAnswer = must[abstentions]("no-usable-answer")
	// NoCertifiedGate: a usable answer held back because the calibration
	// certificate offered to gate it was refused, or was fitted on a score
	// the answer did not carry.
	NoCertifiedGate = must[abstentions]("no-certified-gate")
)

type outcomes struct{}

func (outcomes) words() []string { return []string{"agreed", "disagreed", "abstained", "undecided"} }

// Outcome is how what the analyst produced compares with what a person
// ruled.
type Outcome = word[outcomes]

var (
	// Agreed: the analyst suggested a verdict and the person ruled the same.
	Agreed = must[outcomes]("agreed")
	// Disagreed: the analyst suggested a verdict and the person ruled
	// another.
	Disagreed = must[outcomes]("disagreed")
	// Abstained: the analyst offered no verdict, and a person has ruled;
	// the ruling is the episode's label all the same.
	Abstained = must[outcomes]("abstained")
	// Undecided: no verified person has ruled on the finding since the
	// analyst looked, whatever the analyst produced.
	Undecided = must[outcomes]("undecided")
)

// OutcomeOf is the outcome of what was produced against a person's ruling,
// or against none when person is the zero Verdict.
func OutcomeOf(p Produced, person Verdict) Outcome {
	switch {
	case person.IsZero():
		return Undecided
	case p.Verdict.IsZero():
		return Abstained
	case p.Verdict == person:
		return Agreed
	}
	return Disagreed
}

// ---- identifiers -----------------------------------------------------------

// shape is the pattern an identifier must match whole.
type shape interface{ pattern() *regexp.Regexp }

// ident is a string that matched S's pattern. Like word, its field is
// unexported, so the only way to hold one is a constructor that checked
// it; and each pattern admits no space, so no sentence fits.
type ident[S shape] struct{ s string }

func (x ident[S]) String() string { return x.s }

// IsZero reports that no identifier is set.
func (x ident[S]) IsZero() bool { return x.s == "" }

// MarshalJSON refuses to write an identifier that is not set.
func (x ident[S]) MarshalJSON() ([]byte, error) {
	if _, ok := parseIdent[S](x.s); !ok {
		return nil, errors.New("a required identifier is not set")
	}
	return json.Marshal(x.s)
}

// UnmarshalJSON accepts a string of the identifier's shape and nothing else.
func (x *ident[S]) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	got, ok := parseIdent[S](s)
	if !ok {
		return errors.New("an identifier of the wrong shape")
	}
	*x = got
	return nil
}

func parseIdent[S shape](s string) (ident[S], bool) {
	var sh S
	if !sh.pattern().MatchString(s) {
		return ident[S]{}, false
	}
	return ident[S]{s: s}, true
}

var (
	findingKeyPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)
	entryPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// A model name as endpoints spell them — "llama3.1:8b",
	// "org/Model-7B-Instruct", "name@2026-01-01" — and nothing with a space.
	modelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$`)
)

type findingKeys struct{}

func (findingKeys) pattern() *regexp.Regexp { return findingKeyPattern }

// FindingID is a finding's register key: sixteen hex digits, which is what
// finding.Key derives every finding's id as.
type FindingID = ident[findingKeys]

// FindingIDOf returns s as a finding id, if it has the register key's shape.
func FindingIDOf(s string) (FindingID, bool) { return parseIdent[findingKeys](s) }

type entryHashes struct{}

func (entryHashes) pattern() *regexp.Regexp { return entryPattern }

// Entry is an audit entry's hash: where in the tamper-evident log the
// record an episode came from is.
type Entry = ident[entryHashes]

// EntryOf returns s as an audit entry hash, if it is one.
func EntryOf(s string) (Entry, bool) { return parseIdent[entryHashes](s) }

type modelNames struct{}

func (modelNames) pattern() *regexp.Regexp { return modelPattern }

// Model is the name of the model that produced an episode, as the operator
// configured it — never anything the analyst was shown.
type Model = ident[modelNames]

// ModelOf returns s as a model name, if it has a model name's shape.
func ModelOf(s string) (Model, bool) { return parseIdent[modelNames](s) }

// ---- the episode -----------------------------------------------------------

// Counts is what people ruled on a set of other findings.
type Counts struct {
	Real   int `json:"real"`
	False  int `json:"false_positive"`
	Benign int `json:"benign"`
	Open   int `json:"undecided"`
}

// Records is the part of the facts counted from what people recorded.
type Records struct {
	Rule       Counts `json:"this_rule"`
	Entity     Counts `json:"this_entity"`
	InIncident bool   `json:"in_an_incident,omitempty"`
}

// Volume is the part of the facts counted from what the log said happened.
type Volume struct {
	TimesSeen int `json:"times_seen"`
	AgeHours  int `json:"age_hours"`
	Spread    int `json:"other_entities_open"`
	Sources   int `json:"indicator_sources,omitempty"`
}

// Facts is what the program counted and showed the model, in the same
// shape and under the same names as internal/analyst's Facts — the block
// the model read as counted_by_the_program — so a trainer can put the
// question back together exactly as it was asked, less the text somebody
// else wrote, which an episode never holds.
type Facts struct {
	Kind      FindingKind `json:"kind"`
	Severity  Severity    `json:"severity"`
	Indicator bool        `json:"from_indicator,omitempty"`
	Trial     bool        `json:"rule_on_trial,omitempty"`
	Records   Records     `json:"from_peoples_records"`
	Volume    Volume      `json:"from_the_logs_volume"`
}

// Produced is what the analyst produced: a verdict, or an abstention and
// why, with the confidence it had either way.
type Produced struct {
	Verdict    Verdict    `json:"verdict,omitzero"`
	Confidence float64    `json:"confidence"`
	Abstained  Abstention `json:"abstained,omitzero"`
	// CounterfactualChanged says the verdict did not hold when the
	// attacker-writable text was taken out of the question; the analyst
	// still offered it, flagged, because it was not a closing verdict.
	CounterfactualChanged bool `json:"counterfactual_changed,omitempty"`
}

// Episode is one triage by the analyst and how it turned out.
type Episode struct {
	Format int `json:"format"`
	// Seq and Entry are the analyst's record in the audit log, so the
	// episode can be traced to it and an inclusion proof asked for.
	Seq     int64     `json:"seq"`
	Entry   Entry     `json:"entry"`
	Finding FindingID `json:"finding"`
	// At is when the analyst's record was written.
	At       time.Time `json:"at"`
	Model    Model     `json:"model"`
	Saw      Facts     `json:"saw"`
	Produced Produced  `json:"produced"`
	// Person is the verdict of the last ruling a verified person recorded
	// after the analyst's record, and DecidedSeq that ruling's place in
	// the audit log. Both are absent while nobody has ruled.
	Person     Verdict `json:"person,omitzero"`
	DecidedSeq int64   `json:"decided_seq,omitempty"`
	Outcome    Outcome `json:"outcome"`
}

// Validate refuses an episode that contradicts itself or is missing what
// makes it traceable. It runs before a file is sealed and again on every
// line read back, so neither side relies on the other having run it.
func (e Episode) Validate() error {
	if e.Format != Format {
		return fmt.Errorf("format %d is not one this version reads", e.Format)
	}
	if e.Seq <= 0 {
		return errors.New("an episode names the audit entry it came from, and this names none")
	}
	if e.Entry.IsZero() || e.Finding.IsZero() || e.Model.IsZero() ||
		e.Saw.Kind.IsZero() || e.Saw.Severity.IsZero() {
		return errors.New("an episode is missing an identifier or a word it must have")
	}
	if e.At.IsZero() {
		return errors.New("an episode has no time")
	}
	r, v := e.Saw.Records, e.Saw.Volume
	for _, n := range []int{r.Rule.Real, r.Rule.False, r.Rule.Benign, r.Rule.Open,
		r.Entity.Real, r.Entity.False, r.Entity.Benign, r.Entity.Open,
		v.TimesSeen, v.AgeHours, v.Spread, v.Sources} {
		if n < 0 {
			return errors.New("a count is negative")
		}
	}
	p := e.Produced
	if p.Verdict.IsZero() == p.Abstained.IsZero() {
		return errors.New("the analyst produces a verdict or an abstention, exactly one")
	}
	if math.IsNaN(p.Confidence) || p.Confidence < 0 || p.Confidence > 1 {
		return errors.New("a confidence is between 0 and 1")
	}
	if p.CounterfactualChanged && p.Verdict.IsZero() {
		return errors.New("only a verdict can have changed under the counterfactual")
	}
	if e.Person.IsZero() != (e.DecidedSeq == 0) {
		return errors.New("a ruling and where it was recorded come together")
	}
	if !e.Person.IsZero() && e.DecidedSeq <= e.Seq {
		return errors.New("the ruling was recorded before the analyst looked")
	}
	if e.Outcome != OutcomeOf(p, e.Person) {
		return errors.New("the outcome does not follow from what was produced and ruled")
	}
	return nil
}

// ---- the file --------------------------------------------------------------

// Summary is what a seal says about the episodes above it, and what both
// signatures cover.
type Summary struct {
	// Forge is Context: what this line is and which version wrote it.
	Forge    string `json:"forge"`
	Episodes int    `json:"episodes"`
	// Root is the RFC 6962 Merkle root, in hex, over the episode lines'
	// exact bytes without their newlines, in file order.
	Root      string `json:"merkle_root"`
	Agreed    int    `json:"agreed"`
	Disagreed int    `json:"disagreed"`
	Abstained int    `json:"abstained"`
	Undecided int    `json:"undecided"`
	// ThroughSeq is the last audit entry the exporter read: the same log up
	// to here gives the same episodes again.
	ThroughSeq int64     `json:"through_seq"`
	ExportedAt time.Time `json:"exported_at"`
}

// Signature is both halves of the dual signature over a Summary.
type Signature struct {
	// KeyID is the dual key's fingerprint in Context.
	KeyID   string `json:"key_id"`
	Ed25519 string `json:"ed25519"`
	MLDSA65 string `json:"mldsa_65"`
}

// sealLine is the file's last line.
type sealLine struct {
	Summary
	Signature Signature `json:"signature"`
}

// KeyID is the fingerprint a seal names its key by.
func KeyID(pub pack.KeyPublic) (string, error) { return pack.KeyIDIn(Context, pub) }

// message is the exact bytes both algorithms sign: the context, a NUL, then
// the summary. The context leads the bytes so the Ed25519 half is bound to
// this domain as the ML-DSA half is by its context parameter, and no
// signature made for a proof, a scorecard or a pack can be presented as one
// over episodes.
func message(s Summary) ([]byte, error) {
	body, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(Context), 0), body...), nil
}

func (s *Summary) tally(o Outcome) {
	switch o {
	case Agreed:
		s.Agreed++
	case Disagreed:
		s.Disagreed++
	case Abstained:
		s.Abstained++
	case Undecided:
		s.Undecided++
	}
}

// Seal writes episodes as a signed file and returns it with its summary.
//
// It refuses an empty set. A seal over nothing would be a signed
// statement that something was exported, and the honest record of an
// export that found nothing is no file.
func Seal(eps []Episode, k *pack.Key, throughSeq int64, now time.Time) ([]byte, Summary, error) {
	if len(eps) == 0 {
		return nil, Summary{}, errors.New("there are no episodes, and a seal over none is not written")
	}
	if len(eps) > MaxEpisodes {
		return nil, Summary{}, fmt.Errorf("%d episodes is over the %d one file holds", len(eps), MaxEpisodes)
	}
	sum := Summary{Forge: Context, Episodes: len(eps), ThroughSeq: throughSeq,
		ExportedAt: now.UTC().Truncate(time.Second)}
	var buf bytes.Buffer
	tree := translog.New()
	var prev int64
	for i, e := range eps {
		if err := e.Validate(); err != nil {
			return nil, Summary{}, fmt.Errorf("episode %d: %w", i+1, err)
		}
		if e.Seq <= prev || e.Seq > throughSeq {
			return nil, Summary{}, fmt.Errorf("episode %d is out of the audit log's order", i+1)
		}
		prev = e.Seq
		line, err := json.Marshal(e)
		if err != nil {
			return nil, Summary{}, fmt.Errorf("episode %d: %w", i+1, err)
		}
		tree.Append(line)
		buf.Write(line)
		buf.WriteByte('\n')
		sum.tally(e.Outcome)
	}
	sum.Root = tree.Head().Root
	msg, err := message(sum)
	if err != nil {
		return nil, Summary{}, err
	}
	edSig, mlSig, err := k.DualSign(msg, Context)
	if err != nil {
		return nil, Summary{}, err
	}
	id, err := KeyID(k.PublicKey())
	if err != nil {
		return nil, Summary{}, err
	}
	seal, err := json.Marshal(sealLine{Summary: sum, Signature: Signature{KeyID: id,
		Ed25519: base64.StdEncoding.EncodeToString(edSig),
		MLDSA65: base64.StdEncoding.EncodeToString(mlSig)}})
	if err != nil {
		return nil, Summary{}, err
	}
	buf.Write(seal)
	buf.WriteByte('\n')
	return buf.Bytes(), sum, nil
}

// decodeExactly decodes one line strictly and insists the line is exactly
// what encoding v again produces. Strictly, so a field this version does
// not know is refused by name rather than dropped; exactly, so spacing,
// key order, escapes and duplicate keys — anything that lets two files say
// the same thing in different bytes — are refused too.
func decodeExactly(line []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	again, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(again, line) {
		return errors.New("not in the exact form this version writes")
	}
	return nil
}

// Verify checks a file against a trusted public key and returns what its
// seal says and the episodes it holds. Every byte is accounted for: the
// episode lines by the Merkle root, the summary by both signatures, the
// key's name by the key, and the form of every line by decodeExactly.
func Verify(body []byte, pub pack.KeyPublic) (Summary, []Episode, error) {
	if len(body) > MaxFile {
		return Summary{}, nil, fmt.Errorf("the file is over the %d bytes allowed", MaxFile)
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return Summary{}, nil, errors.New("the file does not end with a whole line; it was cut short or added to")
	}
	lines := bytes.Split(body[:len(body)-1], []byte{'\n'})
	last := lines[len(lines)-1]
	var seal sealLine
	if err := decodeExactly(last, &seal); err != nil {
		return Summary{}, nil, fmt.Errorf("the last line is not a seal: %w", err)
	}
	if seal.Forge != Context {
		return Summary{}, nil, fmt.Errorf("the seal is not an %s seal", Context)
	}
	id, err := KeyID(pub)
	if err != nil {
		return Summary{}, nil, err
	}
	if seal.Signature.KeyID != id {
		return Summary{}, nil, fmt.Errorf("the seal names key %s, and the key trusted here is %s",
			seal.Signature.KeyID, id)
	}
	msg, err := message(seal.Summary)
	if err != nil {
		return Summary{}, nil, err
	}
	if err := pack.DualVerifyBase64(msg, Context, seal.Signature.Ed25519,
		seal.Signature.MLDSA65, pub); err != nil {
		return Summary{}, nil, err
	}

	// Signed, so the summary is now what the signer said. What follows
	// checks the episodes are what it said about them.
	held := lines[:len(lines)-1]
	if seal.Episodes == 0 || len(held) == 0 {
		return Summary{}, nil, errors.New("the seal is over no episodes, which no export signs")
	}
	if seal.Episodes != len(held) {
		return Summary{}, nil, fmt.Errorf("the seal counts %d episodes and the file holds %d",
			seal.Episodes, len(held))
	}
	var got Summary
	tree := translog.New()
	eps := make([]Episode, 0, len(held))
	var prev int64
	for i, line := range held {
		var e Episode
		if err := decodeExactly(line, &e); err != nil {
			return Summary{}, nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if err := e.Validate(); err != nil {
			return Summary{}, nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if e.Seq <= prev || e.Seq > seal.ThroughSeq {
			return Summary{}, nil, fmt.Errorf("line %d is out of the audit log's order", i+1)
		}
		prev = e.Seq
		tree.Append(line)
		got.tally(e.Outcome)
		eps = append(eps, e)
	}
	if tree.Head().Root != seal.Root {
		return Summary{}, nil, errors.New("the episodes' Merkle root is not the one the seal signs: " +
			"a line was changed, moved, removed or added")
	}
	if got.Agreed != seal.Agreed || got.Disagreed != seal.Disagreed ||
		got.Abstained != seal.Abstained || got.Undecided != seal.Undecided {
		return Summary{}, nil, errors.New("the seal's tally of outcomes is not the episodes'")
	}
	return seal.Summary, eps, nil
}
