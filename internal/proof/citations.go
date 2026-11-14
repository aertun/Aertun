// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// An evidence proof: an investigation an AI wrote — a vendor's AI analyst,
// an agent, this program's own analyst — whose citations were run again
// against this store's events (internal/evidence).
//
// An investigation reads as true because it cites things: an alert by its
// id, an address that was seen, a count of sign-ins. Nobody re-runs the
// citations, and a model that invents an alert id writes it in the same
// confident sentence as one that exists. Here every claim comes to one of
// three outcomes, for a reason in a closed set of words: supported by an
// event the store holds, contradicted by the store, or uncheckable because
// the store does not hold the period or the source the claim is about. The
// proof is refuted when any claim is contradicted and names it; proven only
// when every claim is supported and there are at least CitationsMinClaims of
// them; inconclusive otherwise.
//
// Nothing the report's author wrote is carried here except what passed a
// strict parser: a claim's id, an event id, an observable in its canonical
// form, and numbers. The claim, the checks and the failures are rebuilt
// from those and from closed sets whenever the proof is opened, so no
// sentence in it came from the report.

// CitationsVerifier and its version name this verifier.
const (
	CitationsVerifier        = "aertun/evidence"
	CitationsVerifierVersion = "1"
)

// PredicateEvidence is the predicate of an evidence proof.
const PredicateEvidence = "https://aertun.github.io/proof/evidence/v1"

// CitationsMinClaims is the fewest claims a proven evidence proof rests on:
// one or two citations that hold say little about an investigation, and a
// proof of little is inconclusive, never proven.
const CitationsMinClaims = 3

// MaxCitations bounds the claims one proof carries, so a proof stays a
// document.
const MaxCitations = 200

// The kinds of claim.
const (
	// CiteEvent says an event with this id is in the period, and optionally
	// that its class, source and actor are the ones stated.
	CiteEvent = "event-exists"
	// CiteSeen says an observable was seen in the period.
	CiteSeen = "seen"
	// CiteNotSeen says an observable was not seen in the period.
	CiteNotSeen = "not-seen"
	// CiteCount says how many events in the period match a hunt's
	// comparisons: at least, at most or exactly a number.
	CiteCount = "count"
)

// CitationKinds are every kind of claim.
func CitationKinds() []string { return []string{CiteEvent, CiteSeen, CiteNotSeen, CiteCount} }

// The comparisons a count claim makes.
const (
	CountAtLeast = "at-least"
	CountAtMost  = "at-most"
	CountExactly = "exactly"
)

// The outcomes a claim comes to.
const (
	CiteSupported    = "supported"
	CiteContradicted = "contradicted"
	CiteUncheckable  = "uncheckable"
)

// The reasons a claim comes to its outcome.
const (
	// Supported.
	CiteFound      = "found"
	CiteAbsent     = "absent-throughout"
	CiteCountHolds = "count-holds"
	// Contradicted.
	CiteNoSuchEvent      = "no-such-event"
	CiteAttributesDiffer = "attributes-differ"
	CiteNeverSeen        = "never-seen"
	CiteWasSeen          = "seen"
	CiteCountDiffers     = "count-differs"
	// Uncheckable.
	CitePeriodNotHeld = "period-not-held"
	CiteSourceNotHeld = "source-not-held"
	CiteIDsNotHeld    = "ids-not-held"
)

// CitationReasons are every reason, in the order a proof tallies them.
func CitationReasons() []string {
	return []string{CiteFound, CiteAbsent, CiteCountHolds, CiteNoSuchEvent, CiteAttributesDiffer,
		CiteNeverSeen, CiteWasSeen, CiteCountDiffers, CitePeriodNotHeld, CiteSourceNotHeld, CiteIDsNotHeld}
}

// The forms a report comes in.
const (
	// FormReport is the machine-readable report, whose claims its author
	// stated.
	FormReport = "report"
	// FormText is plain text, whose claims are the observables and event ids
	// it cites, each taken as seen in the period.
	FormText = "text"
)

// The types an observable is cited as, each read by a strict parser.
const (
	ObsIPv4   = "ipv4"
	ObsIPv6   = "ipv6"
	ObsDomain = "domain"
	ObsSHA256 = "sha256"
	ObsSHA1   = "sha1"
	ObsMD5    = "md5"
	ObsEmail  = "email"
	// CitedEvent is what an event-exists claim cites: an event id.
	CitedEvent = "event"
)

// ObservableTypes are every observable type.
func ObservableTypes() []string {
	return []string{ObsIPv4, ObsIPv6, ObsDomain, ObsSHA256, ObsSHA1, ObsMD5, ObsEmail}
}

var (
	citeIDShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
	emailLocal  = regexp.MustCompile(`^[a-z0-9._%+-]{1,64}$`)
)

// ValidCitationID reports whether s can name a claim: letters, digits and
// the separators ids use, never spaces or anything a terminal or a reader
// would take for words.
func ValidCitationID(s string) bool { return citeIDShape.MatchString(s) }

// CanonicalObservable is the one form an observable of type typ is carried
// and compared in, and false when value is not one. The parsers are strict:
// an address in its standard spelling only, a domain of letter-digit-hyphen
// labels under an alphabetic top-level label, a digest of exactly its
// length in hexadecimal.
func CanonicalObservable(typ, value string) (string, bool) {
	switch typ {
	case ObsIPv4, ObsIPv6:
		a, err := netip.ParseAddr(value)
		if err != nil || a.Zone() != "" {
			return "", false
		}
		if typ == ObsIPv4 && !a.Is4() || typ == ObsIPv6 && (!a.Is6() || a.Is4In6()) {
			return "", false
		}
		return a.String(), true
	case ObsDomain:
		return canonicalDomain(value)
	case ObsSHA256:
		return canonicalHex(value, 64)
	case ObsSHA1:
		return canonicalHex(value, 40)
	case ObsMD5:
		return canonicalHex(value, 32)
	case ObsEmail:
		// Without an @ the domain is empty, which is not one.
		local, domain, _ := strings.Cut(strings.ToLower(value), "@")
		if !emailLocal.MatchString(local) {
			return "", false
		}
		d, ok := canonicalDomain(domain)
		if !ok {
			return "", false
		}
		return local + "@" + d, true
	}
	return "", false
}

func canonicalHex(s string, n int) (string, bool) {
	s = strings.ToLower(s)
	if len(s) != n {
		return "", false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return s, true
}

func canonicalDomain(s string) (string, bool) {
	s = strings.ToLower(s)
	if len(s) > 253 {
		return "", false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	// An alphabetic top-level label, so an address or a version number is
	// never read as a name.
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return "", false
	}
	for _, c := range tld {
		if c < 'a' || c > 'z' {
			return "", false
		}
	}
	return s, true
}

// DecideCount is what a count claim comes to: observed events matched,
// against the stated number, compared as compare. A count that is short of
// an at-least claim, or of an exact one, is uncheckable rather than
// contradicted when the store does not hold the whole period, because the
// events it lacks could make up the difference; a count already over an
// at-most or exact claim is contradicted whatever the store lacks, because
// more events can only raise it.
func DecideCount(compare string, stated, observed int, covered bool) (outcome, reason string) {
	over, under := observed > stated, observed < stated
	switch compare {
	case CountAtLeast:
		switch {
		case !under:
			return CiteSupported, CiteCountHolds
		case covered:
			return CiteContradicted, CiteCountDiffers
		}
	case CountAtMost:
		switch {
		case over:
			return CiteContradicted, CiteCountDiffers
		case covered:
			return CiteSupported, CiteCountHolds
		}
	case CountExactly:
		switch {
		case over:
			return CiteContradicted, CiteCountDiffers
		case !covered:
		case under:
			return CiteContradicted, CiteCountDiffers
		default:
			return CiteSupported, CiteCountHolds
		}
	}
	return CiteUncheckable, CitePeriodNotHeld
}

// citeRule is one outcome a claim of a kind may come to, for a reason, and
// what the numbers beside it must then say: whether anything was observed
// (1 some, -1 none, 0 either) and whether the store held the period (1 it
// did, -1 it did not, 0 either).
type citeRule struct {
	kind, outcome, reason string
	observed, covered     int
}

var citeRules = []citeRule{
	{CiteEvent, CiteSupported, CiteFound, 1, 0},
	{CiteEvent, CiteContradicted, CiteAttributesDiffer, 1, 0},
	{CiteEvent, CiteContradicted, CiteNoSuchEvent, -1, 1},
	{CiteEvent, CiteUncheckable, CitePeriodNotHeld, -1, -1},
	{CiteEvent, CiteUncheckable, CiteSourceNotHeld, -1, 0},
	{CiteEvent, CiteUncheckable, CiteIDsNotHeld, -1, 0},
	{CiteSeen, CiteSupported, CiteFound, 1, 0},
	{CiteSeen, CiteContradicted, CiteNeverSeen, -1, 1},
	{CiteSeen, CiteUncheckable, CitePeriodNotHeld, -1, -1},
	{CiteSeen, CiteUncheckable, CiteSourceNotHeld, -1, 0},
	{CiteNotSeen, CiteSupported, CiteAbsent, -1, 1},
	{CiteNotSeen, CiteContradicted, CiteWasSeen, 1, 0},
	{CiteNotSeen, CiteUncheckable, CitePeriodNotHeld, -1, -1},
	{CiteNotSeen, CiteUncheckable, CiteSourceNotHeld, -1, 0},
	{CiteCount, CiteUncheckable, CiteSourceNotHeld, -1, 0},
}

func signOK(want int, got bool) bool { return want == 0 || (want > 0) == got }

// CitationOutcome is what one claim came to.
type CitationOutcome struct {
	// ID is the claim's id, as the report gave it or as the extraction from
	// text numbered it.
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// CitedType and Cited name what the claim is about: an event id, or an
	// observable in its canonical form. Both are empty for a count.
	CitedType string `json:"cited_type,omitempty"`
	Cited     string `json:"cited,omitempty"`
	// Compare and Stated are a count claim's comparison and number.
	Compare string `json:"compare,omitempty"`
	Stated  int    `json:"stated,omitempty"`
	// Observed is how many events in the period carried the event id or the
	// observable, or matched the count's comparisons.
	Observed int    `json:"observed"`
	Outcome  string `json:"outcome"`
	Reason   string `json:"reason"`
	// Extracted marks a claim read out of plain text rather than stated.
	Extracted bool `json:"extracted,omitempty"`
}

// CitationsEvidence is what an investigation's citations came to.
type CitationsEvidence struct {
	// Source is the short name of whoever wrote the investigation; Form
	// whether it was a report or plain text.
	Source string `json:"source"`
	Form   string `json:"form"`
	// Since and Until are the period the claims are about.
	Since string `json:"since"`
	Until string `json:"until"`
	// HeldFrom and HeldUntil are the arrivals the store held when the proof
	// was made, both empty when it held none; Covered is whether they span
	// the period.
	HeldFrom  string `json:"held_from,omitempty"`
	HeldUntil string `json:"held_until,omitempty"`
	Covered   bool   `json:"covered"`
	// EventsRead is how many events in the period were read.
	EventsRead   int               `json:"events_read"`
	Claims       int               `json:"claims"`
	Extracted    int               `json:"extracted"`
	Supported    int               `json:"supported"`
	Contradicted int               `json:"contradicted"`
	Uncheckable  int               `json:"uncheckable"`
	Outcomes     []CitationOutcome `json:"outcomes"`
}

// CitationsInput is what an evidence proof is made from.
type CitationsInput struct {
	Source, Form string
	// Report is the investigation as read: what the subject's digest is
	// over.
	Report              []byte
	Since, Until        time.Time
	HeldFrom, HeldUntil time.Time
	EventsRead          int
	Outcomes            []CitationOutcome
	Materials           []Material
	Program             string
	Now                 time.Time
}

// Covers reports whether arrivals held from from to until span the period
// since to until. Nothing held covers nothing.
func Covers(from, until, since, end time.Time) bool {
	return !from.IsZero() && !from.After(since) && !until.Before(end)
}

// ProveCitations builds the unsigned statement.
func ProveCitations(in CitationsInput) (*Statement, error) {
	ev := &CitationsEvidence{Source: in.Source, Form: in.Form,
		Since: in.Since.UTC().Format(time.RFC3339), Until: in.Until.UTC().Format(time.RFC3339),
		Covered: Covers(in.HeldFrom, in.HeldUntil, in.Since, in.Until), EventsRead: in.EventsRead,
		Outcomes: append([]CitationOutcome{}, in.Outcomes...)}
	if !in.HeldFrom.IsZero() {
		ev.HeldFrom = in.HeldFrom.UTC().Format(time.RFC3339)
		ev.HeldUntil = in.HeldUntil.UTC().Format(time.RFC3339)
	}
	ev.tally()
	if len(in.Report) == 0 {
		return nil, fmt.Errorf("an evidence proof rests on the report it checked")
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "evidence/" + in.Source, Digest: SHA256(in.Report)}},
		PredicateType: PredicateEvidence,
		Predicate: Predicate{
			Claim:   ev.claim(),
			Verdict: ev.verdict(),
			Verifier: VerifierID{ID: CitationsVerifier, Version: CitationsVerifierVersion,
				Program: in.Program},
			Materials:  append([]Material{}, in.Materials...),
			Checks:     ev.checks(),
			Citations:  ev,
			VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *CitationsEvidence) tally() {
	ev.Claims, ev.Extracted, ev.Supported, ev.Contradicted, ev.Uncheckable = len(ev.Outcomes), 0, 0, 0, 0
	for _, o := range ev.Outcomes {
		if o.Extracted {
			ev.Extracted++
		}
		switch o.Outcome {
		case CiteSupported:
			ev.Supported++
		case CiteContradicted:
			ev.Contradicted++
		case CiteUncheckable:
			ev.Uncheckable++
		}
	}
}

func (ev *CitationsEvidence) claim() string {
	if ev.Form == FormText {
		return fmt.Sprintf("Every observable and event id cited in the text %s wrote was seen in the "+
			"events this store holds from %s to %s.", ev.Source, ev.Since, ev.Until)
	}
	return fmt.Sprintf("Every claim in the report %s wrote about %s to %s holds against the events "+
		"this store holds for that period.", ev.Source, ev.Since, ev.Until)
}

func (ev *CitationsEvidence) verdict() Verdict {
	switch {
	case ev.Contradicted > 0:
		return Refuted
	case ev.Claims >= CitationsMinClaims && ev.Supported == ev.Claims:
		return Proven
	}
	return Inconclusive
}

// citeFailure is how a proof names a contradicted claim: its id and the
// reason, both from strict shapes and closed sets.
func citeFailure(o CitationOutcome) string { return "claim " + o.ID + ": " + o.Reason }

func (ev *CitationsEvidence) checks() []Check {
	from := "a report, as its author stated them"
	if ev.Form == FormText {
		from = "plain text, each an observable or event id it cites, taken as seen in the period"
	}
	read := Check{Name: "read", Passed: true,
		Detail: fmt.Sprintf("%d claim(s) from %s, %d of them extracted; %d event(s) in the period read "+
			"from the store", ev.Claims, from, ev.Extracted, ev.EventsRead)}
	coverage := Check{Name: "coverage", Passed: true,
		Detail: "the store holds no events, so it holds none of the period"}
	if ev.HeldFrom != "" {
		word := "does not span"
		if ev.Covered {
			word = "spans"
		}
		coverage.Detail = fmt.Sprintf("the store holds events that arrived from %s to %s, which %s "+
			"the period", ev.HeldFrom, ev.HeldUntil, word)
	}
	counts := map[string]int{}
	var failures []string
	for _, o := range ev.Outcomes {
		counts[o.Reason]++
		if o.Outcome == CiteContradicted {
			failures = append(failures, citeFailure(o))
		}
	}
	var parts []string
	for _, r := range CitationReasons() {
		if n := counts[r]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, r))
		}
	}
	held := Check{Name: "held-to-the-store", Passed: ev.Contradicted == 0,
		Detail: fmt.Sprintf("%d supported, %d contradicted, %d uncheckable (%s); proven needs every "+
			"claim supported and at least %d of them", ev.Supported, ev.Contradicted, ev.Uncheckable,
			strings.Join(parts, ", "), CitationsMinClaims)}
	shown, more := capped(failures)
	held.Failures = shown
	if more > 0 {
		held.Detail += fmt.Sprintf("; %d more not listed", more)
	}
	return []Check{read, coverage, held}
}

// valid holds one outcome to its kind's shapes, closed sets and the rules
// that tie its outcome to its numbers.
func (o CitationOutcome) valid(form string, covered bool) bool {
	if !ValidCitationID(o.ID) || o.Observed < 0 || o.Extracted != (form == FormText) {
		return false
	}
	// Text yields only what it cites, taken as seen.
	if form == FormText && o.Kind != CiteEvent && o.Kind != CiteSeen {
		return false
	}
	switch o.Kind {
	case CiteEvent:
		if o.CitedType != CitedEvent || !telemetry.ValidAlertID(o.Cited) || o.Compare != "" || o.Stated != 0 {
			return false
		}
	case CiteSeen, CiteNotSeen:
		if c, ok := CanonicalObservable(o.CitedType, o.Cited); !ok || c != o.Cited ||
			o.Compare != "" || o.Stated != 0 {
			return false
		}
	case CiteCount:
		if o.CitedType != "" || o.Cited != "" || o.Stated < 0 {
			return false
		}
		switch o.Compare {
		case CountAtLeast, CountAtMost, CountExactly:
		default:
			return false
		}
		if o.Reason != CiteSourceNotHeld {
			out, why := DecideCount(o.Compare, o.Stated, o.Observed, covered)
			return o.Outcome == out && o.Reason == why
		}
	}
	// A kind this version does not have matches no rule, and is refused
	// here with every reason it might give.
	for _, r := range citeRules {
		if r.kind == o.Kind && r.outcome == o.Outcome && r.reason == o.Reason {
			return signOK(r.observed, o.Observed > 0) && signOK(r.covered, covered)
		}
	}
	return false
}

func (ev *CitationsEvidence) validate(s *Statement) error {
	if !ValidVerdictSource(ev.Source) || (ev.Form != FormReport && ev.Form != FormText) {
		return fmt.Errorf("an evidence proof names who wrote the investigation and the form it came in")
	}
	if !validPeriod(ev.Since, ev.Until) {
		return fmt.Errorf("an evidence proof's period starts before it ends")
	}
	since, _ := time.Parse(time.RFC3339, ev.Since)
	until, _ := time.Parse(time.RFC3339, ev.Until)
	var from, to time.Time
	if ev.HeldFrom != "" || ev.HeldUntil != "" {
		var err1, err2 error
		from, err1 = time.Parse(time.RFC3339, ev.HeldFrom)
		to, err2 = time.Parse(time.RFC3339, ev.HeldUntil)
		if err1 != nil || err2 != nil || to.Before(from) {
			return fmt.Errorf("an evidence proof says what the store held as two times in order, or nothing")
		}
	}
	if ev.Covered != Covers(from, to, since, until) {
		return fmt.Errorf("what the store held does not say whether it spans the period")
	}
	if len(ev.Outcomes) > MaxCitations || ev.EventsRead < 0 {
		return fmt.Errorf("an evidence proof carries at most %d claims", MaxCitations)
	}
	ids := map[string]bool{}
	for _, o := range ev.Outcomes {
		if ids[o.ID] || !o.valid(ev.Form, ev.Covered) {
			return fmt.Errorf("a claim's outcome is not one its kind, its numbers and the store's " +
				"coverage allow, or its id is not one shape or is given twice")
		}
		ids[o.ID] = true
	}
	counted := *ev
	counted.tally()
	if counted.Claims != ev.Claims || counted.Extracted != ev.Extracted || counted.Supported != ev.Supported ||
		counted.Contradicted != ev.Contradicted || counted.Uncheckable != ev.Uncheckable {
		return fmt.Errorf("the claims' counts do not add up")
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("the counts make this %s, not %s", want, s.Predicate.Verdict)
	}
	if len(s.Subject) != 1 || s.Subject[0].Name != "evidence/"+ev.Source {
		return fmt.Errorf("the subject is not the report")
	}
	if s.Predicate.Claim != ev.claim() {
		return fmt.Errorf("the claim is not the sentence its evidence makes")
	}
	// The failures too: each is rebuilt from an outcome, so the checks are
	// compared whole.
	a, _ := json.Marshal(s.Predicate.Checks)
	b, _ := json.Marshal(ev.checks())
	if string(a) != string(b) {
		return fmt.Errorf("the checks are not the ones its evidence makes")
	}
	return nil
}
