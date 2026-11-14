// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package evidence runs an investigation's citations again against the
// events this program holds.
//
// # Why
//
// An AI analyst's investigation — a vendor's, an agent's, this program's own
// — persuades by what it cites: an alert by its id, an address that was
// seen, a count of failed sign-ins. Citations are cheap to write and nobody
// re-runs them, and a model that invents an alert id writes it in the same
// sentence as one that exists. This package reads the claims an
// investigation makes and checks each against the store, so what is signed
// (internal/proof) is what held, not what was said.
//
// # What a report may say
//
// A report is strict JSON (Format): who wrote it, the period it covers, and
// claims, each with an id and a kind from a closed set — an event id exists;
// an observable was seen, or was not; a count of events matching a hunt's
// comparisons is at least, at most or exactly a number. Free text — a title,
// a summary, each claim's statement — is accepted so a report can be read by
// a person, and never read here. Plain text is accepted too: the
// observables and tagged event ids it cites, each strictly parsed, become
// claims that they were seen in the period, and nothing else in the text is
// kept.
//
// # What a claim comes to
//
// Supported, contradicted or uncheckable, for a reason in a closed set
// (internal/proof). An observable is seen when it is a whole value an event
// carries or a whole word inside one (carried). Finding something is
// evidence however little of the period the store holds; not finding it is evidence only when the store
// holds the whole period, and of the source the claim names. Absence over a
// gap is uncheckable, said as such, never contradicted.
package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/indicator"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/telemetry"
)

// Format names the report format and its version.
const Format = "aertun/evidence-report/v1"

// MaxReport bounds a report, JSON or text, in bytes.
const MaxReport = 1 << 20

// MaxPeriod bounds the period a report covers: a longer one is several
// reports, and one read of the store.
const MaxPeriod = 31 * 24 * time.Hour

// MaxWhere bounds the comparisons one count claim makes, and MaxValue a
// comparison's value or a stated actor.
const (
	MaxWhere = 4
	MaxValue = 256
)

// HuntOps are the comparisons a count claim may make: the console hunt's,
// and no more.
var HuntOps = []detect.Op{detect.Equals, detect.Contains, detect.Prefix, detect.Suffix}

// Claim is one claim, parsed.
type Claim struct {
	ID   string
	Kind string
	// Event is an event-exists claim's event id: the platform's own id an
	// event carries (telemetry.AlertField). Class, EventSource and Actor are
	// what it says about that event, each zero when not stated.
	Event string
	Class telemetry.Class
	Actor string
	// EventSource is, for an event-exists claim, the source the event is
	// said to have come from; for the other kinds, the only source whose
	// events count.
	EventSource string
	// ObsType and Obs are a seen or not-seen claim's observable, Obs in its
	// canonical form.
	ObsType, Obs string
	// Where, Compare and N are a count claim's comparisons, all of which an
	// event must satisfy, and the number it is compared with.
	Where   []detect.Match
	Compare string
	N       int
	// Extracted marks a claim read out of plain text.
	Extracted bool
}

// Report is an investigation, parsed.
type Report struct {
	Source       string
	Form         string
	Since, Until time.Time
	Claims       []Claim
}

// Text is what plain text does not say for itself: who wrote it and the
// period it is about, from whoever hands it in.
type Text struct {
	Source       string
	Since, Until time.Time
}

func (t Text) zero() bool { return t.Source == "" && t.Since.IsZero() && t.Until.IsZero() }

// The report as written. Title, Summary and Statement are free text for a
// person to read, and never read here.
type wireReport struct {
	Format  string      `json:"format"`
	Source  string      `json:"source"`
	Title   string      `json:"title,omitempty"`
	Summary string      `json:"summary,omitempty"`
	Since   string      `json:"since"`
	Until   string      `json:"until"`
	Claims  []wireClaim `json:"claims"`
}

type wireClaim struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Statement   string          `json:"statement,omitempty"`
	Event       string          `json:"event,omitempty"`
	Class       uint32          `json:"class,omitempty"`
	EventSource string          `json:"event_source,omitempty"`
	Actor       string          `json:"actor,omitempty"`
	Observable  *wireObservable `json:"observable,omitempty"`
	Where       []wireWhere     `json:"where,omitempty"`
	Compare     string          `json:"compare,omitempty"`
	N           *int            `json:"n,omitempty"`
}

type wireObservable struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type wireWhere struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

var sourceShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}$`)

// Parse reads a report. A body whose first character is { is a report and
// nothing else: it states its own author and period, so t must be zero. Any
// other body is plain text, and t says what the text does not. Every error
// names a claim by its place in the report and never repeats what it says.
func Parse(body []byte, t Text) (Report, error) {
	if len(body) > MaxReport {
		return Report{}, fmt.Errorf("a report is at most %d bytes", MaxReport)
	}
	if trimmed := bytes.TrimLeft(body, " \t\r\n"); len(trimmed) > 0 && trimmed[0] == '{' {
		if !t.zero() {
			return Report{}, errors.New("a report states its own source and period; " +
				"--source, --since and --until are for plain text")
		}
		return parseJSON(body)
	}
	if !proof.ValidVerdictSource(t.Source) {
		return Report{}, errors.New("plain text needs --source: who wrote it, by a short name " +
			"you choose (2 to 32 of a-z, 0-9 and -, starting with a letter)")
	}
	if err := checkPeriod(t.Since, t.Until); err != nil {
		return Report{}, err
	}
	claims, err := Extract(body)
	if err != nil {
		return Report{}, err
	}
	return Report{Source: t.Source, Form: proof.FormText, Since: t.Since.UTC(), Until: t.Until.UTC(),
		Claims: claims}, nil
}

func checkPeriod(since, until time.Time) error {
	// A time not given is the zero time, which is before any other and
	// further from it than the bound, so neither needs saying twice.
	if !since.Before(until) || until.Sub(since) > MaxPeriod {
		return fmt.Errorf("the period starts before it ends and is at most %d days",
			int(MaxPeriod.Hours()/24))
	}
	return nil
}

func parseJSON(body []byte) (Report, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var w wireReport
	if err := dec.Decode(&w); err != nil {
		return Report{}, errors.New("the report is not one in the format: it is not JSON, or it " +
			"has a field the format does not, or a value of the wrong type")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Report{}, errors.New("the report has something after its closing brace")
	}
	if w.Format != Format {
		return Report{}, fmt.Errorf("the report's format is %s", Format)
	}
	if !proof.ValidVerdictSource(w.Source) {
		return Report{}, errors.New("the report's source is 2 to 32 of a-z, 0-9 and -, starting with a letter")
	}
	since, err1 := time.Parse(time.RFC3339, w.Since)
	until, err2 := time.Parse(time.RFC3339, w.Until)
	if err1 != nil || err2 != nil {
		return Report{}, errors.New("the report's since and until are RFC 3339 times")
	}
	if err := checkPeriod(since, until); err != nil {
		return Report{}, err
	}
	if len(w.Claims) > proof.MaxCitations {
		return Report{}, fmt.Errorf("a report makes at most %d claims", proof.MaxCitations)
	}
	r := Report{Source: w.Source, Form: proof.FormReport, Since: since.UTC(), Until: until.UTC()}
	ids := map[string]bool{}
	for i, wc := range w.Claims {
		c, err := parseClaim(wc)
		if err != nil {
			return Report{}, fmt.Errorf("claim %d: %w", i+1, err)
		}
		if ids[c.ID] {
			return Report{}, fmt.Errorf("claim %d: its id is another claim's", i+1)
		}
		ids[c.ID] = true
		r.Claims = append(r.Claims, c)
	}
	return r, nil
}

// takes is the parameters each kind of claim takes, beside its id, kind and
// statement; any other is refused, so a claim cannot carry a condition the
// check would not read.
var takes = map[string]map[string]bool{
	proof.CiteEvent:   {"event": true, "class": true, "event_source": true, "actor": true},
	proof.CiteSeen:    {"observable": true, "event_source": true},
	proof.CiteNotSeen: {"observable": true, "event_source": true},
	proof.CiteCount:   {"where": true, "compare": true, "n": true, "event_source": true},
}

func parseClaim(wc wireClaim) (Claim, error) {
	if !proof.ValidCitationID(wc.ID) {
		return Claim{}, errors.New("its id is 1 to 32 of letters, digits, '.', '_' and '-', " +
			"starting with a letter or digit")
	}
	allowed, ok := takes[wc.Kind]
	if !ok {
		return Claim{}, fmt.Errorf("its kind is one of %s", strings.Join(proof.CitationKinds(), ", "))
	}
	given := map[string]bool{"event": wc.Event != "", "class": wc.Class != 0,
		"event_source": wc.EventSource != "", "actor": wc.Actor != "", "observable": wc.Observable != nil,
		"where": wc.Where != nil, "compare": wc.Compare != "", "n": wc.N != nil}
	for name, set := range given {
		if set && !allowed[name] {
			return Claim{}, fmt.Errorf("a %s claim takes no %s", wc.Kind, name)
		}
	}
	c := Claim{ID: wc.ID, Kind: wc.Kind}
	if wc.EventSource != "" {
		if !sourceShape.MatchString(wc.EventSource) {
			return Claim{}, errors.New("its event_source is a connector's name, such as okta/system")
		}
		c.EventSource = wc.EventSource
	}
	switch wc.Kind {
	case proof.CiteEvent:
		if !telemetry.ValidAlertID(wc.Event) {
			return Claim{}, errors.New("its event is an event id: letters, digits and . _ : -, " +
				"starting with a letter or digit, at most 128")
		}
		if wc.Class != 0 && !telemetry.Class(wc.Class).Valid() {
			return Claim{}, errors.New("its class is not an event class")
		}
		if len(wc.Actor) > MaxValue {
			return Claim{}, fmt.Errorf("its actor is at most %d bytes", MaxValue)
		}
		c.Event, c.Class, c.Actor = wc.Event, telemetry.Class(wc.Class), wc.Actor
	case proof.CiteSeen, proof.CiteNotSeen:
		if wc.Observable == nil {
			return Claim{}, errors.New("it names no observable")
		}
		v, ok := proof.CanonicalObservable(wc.Observable.Type, wc.Observable.Value)
		if !ok {
			return Claim{}, fmt.Errorf("its observable is not a %s, which is one of %s",
				typeWord(wc.Observable.Type), strings.Join(proof.ObservableTypes(), ", "))
		}
		c.ObsType, c.Obs = wc.Observable.Type, v
	case proof.CiteCount:
		if len(wc.Where) == 0 || len(wc.Where) > MaxWhere {
			return Claim{}, fmt.Errorf("it makes 1 to %d comparisons", MaxWhere)
		}
		for j, w := range wc.Where {
			m, err := comparison(w)
			if err != nil {
				return Claim{}, fmt.Errorf("comparison %d: %w", j+1, err)
			}
			c.Where = append(c.Where, m)
		}
		switch wc.Compare {
		case proof.CountAtLeast, proof.CountAtMost, proof.CountExactly:
		default:
			return Claim{}, fmt.Errorf("its compare is %s, %s or %s", proof.CountAtLeast,
				proof.CountAtMost, proof.CountExactly)
		}
		if wc.N == nil || *wc.N < 0 || *wc.N > 1<<30 {
			return Claim{}, errors.New("its n is a whole number, at least 0")
		}
		c.Compare, c.N = wc.Compare, *wc.N
	}
	return c, nil
}

// typeWord is an observable type as an error may name it: one of the closed
// set, or a word that is not the author's.
func typeWord(t string) string {
	for _, k := range proof.ObservableTypes() {
		if k == t {
			return t
		}
	}
	return "known type"
}

func comparison(w wireWhere) (detect.Match, error) {
	opOK := false
	for _, o := range HuntOps {
		opOK = opOK || string(o) == w.Op
	}
	if !opOK {
		return detect.Match{}, errors.New("its op is equals, contains, prefix or suffix")
	}
	if len(w.Field) > 64 || len(w.Value) > MaxValue {
		return detect.Match{}, fmt.Errorf("its field is at most 64 bytes and its value at most %d", MaxValue)
	}
	m := detect.Match{Field: w.Field, Op: detect.Op(w.Op), Values: []string{w.Value}}
	if m.Usable() != nil {
		return detect.Match{}, errors.New("it names no field or compares against nothing")
	}
	return m, nil
}

// textTLDs are the top-level labels a name in plain text must end in to be
// taken as a domain: prose is full of file names and dotted words, and a
// name under any other label is cited in a report instead, where its author
// says it is a domain.
var textTLDs = map[string]bool{}

func init() {
	for _, t := range strings.Fields(`com net org info biz io co ai app dev xyz top site online
		club shop live cloud tech me cc tv ws pw ru su cn uk de fr nl eu jp kr in br au ca us ch
		se no pl it es ua by kz ir kp tk ml ga cf gq vn id tr hk tw sg example test invalid onion`) {
		textTLDs[t] = true
	}
}

// eventTags are what mark an event id in plain text: "event:ID" or
// "alert:ID", with nothing between.
var eventTags = []string{"event:", "alert:"}

// Extract reads the observables and tagged event ids plain text cites, each
// strictly parsed, as claims that they were seen in the period, numbered x1,
// x2, … in the order they first appear. Nothing else in the text is kept.
func Extract(body []byte) ([]Claim, error) {
	text := indicator.Refang(string(body))
	tokens := strings.FieldsFunc(text, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			strings.ContainsRune("._:@%+-", r))
	})
	seen := map[string]bool{}
	var out []Claim
	for _, tok := range tokens {
		tok = strings.TrimLeft(strings.TrimRight(tok, ".,;:"), ".,;")
		c, ok := cited(tok)
		if !ok || seen[c.ObsType+" "+c.Obs+c.Event] {
			continue
		}
		seen[c.ObsType+" "+c.Obs+c.Event] = true
		if len(out) == proof.MaxCitations {
			return nil, fmt.Errorf("the text cites more than %d things; a report says which "+
				"of them it claims", proof.MaxCitations)
		}
		c.ID, c.Extracted = fmt.Sprintf("x%d", len(out)+1), true
		out = append(out, c)
	}
	return out, nil
}

// cited is what one word of text cites, if anything.
func cited(tok string) (Claim, bool) {
	lower := strings.ToLower(tok)
	for _, tag := range eventTags {
		if id, ok := strings.CutPrefix(lower, tag); ok {
			id = tok[len(tag):]
			if telemetry.ValidAlertID(id) {
				return Claim{Kind: proof.CiteEvent, Event: id}, true
			}
			return Claim{}, false
		}
	}
	try := func(typ string) (Claim, bool) {
		v, ok := proof.CanonicalObservable(typ, tok)
		return Claim{Kind: proof.CiteSeen, ObsType: typ, Obs: v}, ok
	}
	switch {
	case strings.Contains(tok, "@"):
		return try(proof.ObsEmail)
	case strings.Contains(tok, ":"):
		return try(proof.ObsIPv6)
	}
	for _, typ := range []string{proof.ObsIPv4, proof.ObsSHA256, proof.ObsSHA1, proof.ObsMD5} {
		if c, ok := try(typ); ok {
			return c, true
		}
	}
	if c, ok := try(proof.ObsDomain); ok && textTLDs[c.Obs[strings.LastIndex(c.Obs, ".")+1:]] {
		return c, true
	}
	return Claim{}, false
}

// Result is what one claim came to.
type Result struct {
	Claim    Claim
	Observed int
	Outcome  string
	Reason   string
}

// outcome is the result as a proof carries it: the claim's id, kind and
// what it cites, from strict shapes and closed sets, and the numbers.
func (r Result) outcome() proof.CitationOutcome {
	c := r.Claim
	o := proof.CitationOutcome{ID: c.ID, Kind: c.Kind, Observed: r.Observed, Outcome: r.Outcome,
		Reason: r.Reason, Extracted: c.Extracted}
	switch c.Kind {
	case proof.CiteEvent:
		o.CitedType, o.Cited = proof.CitedEvent, c.Event
	case proof.CiteSeen, proof.CiteNotSeen:
		o.CitedType, o.Cited = c.ObsType, c.Obs
	case proof.CiteCount:
		o.Compare, o.Stated = c.Compare, c.N
	}
	return o
}

// Outcomes are results as a proof carries them.
func Outcomes(rs []Result) []proof.CitationOutcome {
	out := make([]proof.CitationOutcome, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.outcome())
	}
	return out
}

// Coverage is the arrivals the store holds: From the earliest, Until the
// latest, From zero when it holds none.
type Coverage struct{ From, Until time.Time }

// valueKey is the form a field's whole value is looked up in: an address by
// its canonical spelling, anything else lower-cased.
func valueKey(v string) string {
	v = strings.TrimSpace(v)
	if a, err := netip.ParseAddr(v); err == nil && a.Zone() == "" {
		return "ip " + a.Unmap().String()
	}
	return "v " + strings.ToLower(v)
}

func claimKey(c Claim) string {
	if c.ObsType == proof.ObsIPv4 || c.ObsType == proof.ObsIPv6 {
		return "ip " + c.Obs
	}
	return "v " + c.Obs
}

// carried are the keys of everything an event carries where an observable
// could be: the whole value of each of its observables, of its actor, target
// and device and of each raw field, and every whole word inside those values
// and its message — so a domain inside a URL, an address beside a port, a
// digest in a path and the domain of an email address all count as seen.
//
// A claim that something was seen and is found nowhere refutes a report, so
// the reading errs towards having seen it; but only whole words count, so
// notevil.example is never evil.example, and a longer name is never the
// shorter one inside it.
func carried(e telemetry.Event) map[string]bool {
	out := map[string]bool{}
	add := func(v string) {
		if v == "" {
			return
		}
		out[valueKey(v)] = true
		for _, w := range words(v) {
			out[valueKey(w)] = true
		}
	}
	for _, o := range e.Observables {
		add(o.Value)
	}
	for _, id := range []telemetry.ID{e.Actor, e.Target, e.Device} {
		add(id.Value)
	}
	for _, v := range e.Raw {
		add(v)
	}
	add(e.Message)
	return out
}

// maxWordsIn bounds how much of one value is read for words: a field longer
// than this is a document, and its whole value is still compared.
const maxWordsIn = 64 << 10

// words are the whole words of a value an observable could be: runs of the
// characters names, addresses and digests are made of, split everywhere
// else, with an email address's domain beside it; and, for IPv6, runs of
// hexadecimal digits, colons and dots, which the first split breaks at
// every colon.
func words(v string) []string {
	if len(v) > maxWordsIn {
		v = v[:maxWordsIn]
	}
	var out []string
	for _, w := range strings.FieldsFunc(v, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '_' || r == '%' || r == '+' || r == '@' || r == '-')
	}) {
		w = strings.Trim(w, ".-")
		if w == "" {
			continue
		}
		out = append(out, w)
		if _, domain, ok := strings.Cut(w, "@"); ok && domain != "" {
			out = append(out, domain)
		}
		// A digest stored as a file's name keeps its extension: the run
		// between dots that is exactly a digest's length in hexadecimal.
		if strings.Contains(w, ".") {
			for _, part := range strings.Split(w, ".") {
				if n := len(part); (n == 32 || n == 40 || n == 64) && isHex(part) {
					out = append(out, part)
				}
			}
		}
	}
	if strings.Count(v, ":") >= 2 {
		for _, w := range strings.FieldsFunc(v, func(r rune) bool {
			return !(r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9' ||
				r == ':' || r == '.')
		}) {
			if strings.Count(w, ":") >= 2 {
				out = append(out, w)
			}
		}
	}
	return out
}

// Check runs every claim against the events read hands it, in one pass.
// read is the store's events in the report's period by their own time; any
// event outside the period it hands over is ignored, so what is counted is
// the period whatever the reader does. It answers each claim's result, in
// the report's order, and how many events in the period were read.
func Check(r Report, cov Coverage, read func(func(telemetry.Event) error) error) ([]Result, int, error) {
	n := len(r.Claims)
	observed, matched := make([]int, n), make([]int, n)
	byObs, byEvent := map[string][]int{}, map[string][]int{}
	var counts []int
	sources := map[string]bool{} // the sources whose events were read
	ids := map[string]bool{}     // the sources whose events carried an event id, "" for any
	for i, c := range r.Claims {
		switch c.Kind {
		case proof.CiteEvent:
			byEvent[c.Event] = append(byEvent[c.Event], i)
		case proof.CiteSeen, proof.CiteNotSeen:
			byObs[claimKey(c)] = append(byObs[claimKey(c)], i)
		case proof.CiteCount:
			counts = append(counts, i)
		}
	}
	events := 0
	err := read(func(e telemetry.Event) error {
		if e.Time.Before(r.Since) || !e.Time.Before(r.Until) {
			return nil
		}
		events++
		sources[e.Source] = true
		if id := e.Raw[telemetry.AlertField]; telemetry.ValidAlertID(id) {
			ids[""], ids[e.Source] = true, true
			for _, i := range byEvent[id] {
				observed[i]++
				if attributesHold(r.Claims[i], e) {
					matched[i]++
				}
			}
		}
		if len(byObs) > 0 {
			for k := range carried(e) {
				for _, i := range byObs[k] {
					if from := r.Claims[i].EventSource; from == "" || from == e.Source {
						observed[i]++
					}
				}
			}
		}
		if len(counts) > 0 {
			f := e.Fields()
			for _, i := range counts {
				if c := r.Claims[i]; (c.EventSource == "" || c.EventSource == e.Source) && all(c.Where, f) {
					observed[i]++
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	covered := proof.Covers(cov.From, cov.Until, r.Since, r.Until)
	out := make([]Result, 0, n)
	for i, c := range r.Claims {
		res := Result{Claim: c, Observed: observed[i]}
		lacksSource := c.EventSource != "" && !sources[c.EventSource]
		switch c.Kind {
		case proof.CiteEvent:
			switch {
			case matched[i] > 0:
				res.Outcome, res.Reason = proof.CiteSupported, proof.CiteFound
			case observed[i] > 0:
				res.Outcome, res.Reason = proof.CiteContradicted, proof.CiteAttributesDiffer
			case lacksSource:
				res.Outcome, res.Reason = proof.CiteUncheckable, proof.CiteSourceNotHeld
			case !ids[c.EventSource]:
				res.Outcome, res.Reason = proof.CiteUncheckable, proof.CiteIDsNotHeld
			case !covered:
				res.Outcome, res.Reason = proof.CiteUncheckable, proof.CitePeriodNotHeld
			default:
				res.Outcome, res.Reason = proof.CiteContradicted, proof.CiteNoSuchEvent
			}
		case proof.CiteSeen, proof.CiteNotSeen:
			found, absent := proof.CiteSupported, proof.CiteContradicted
			foundWhy, absentWhy := proof.CiteFound, proof.CiteNeverSeen
			if c.Kind == proof.CiteNotSeen {
				found, absent = proof.CiteContradicted, proof.CiteSupported
				foundWhy, absentWhy = proof.CiteWasSeen, proof.CiteAbsent
			}
			switch {
			case observed[i] > 0:
				res.Outcome, res.Reason = found, foundWhy
			case lacksSource:
				res.Outcome, res.Reason = proof.CiteUncheckable, proof.CiteSourceNotHeld
			case !covered:
				res.Outcome, res.Reason = proof.CiteUncheckable, proof.CitePeriodNotHeld
			default:
				res.Outcome, res.Reason = absent, absentWhy
			}
		case proof.CiteCount:
			if lacksSource {
				res.Outcome, res.Reason = proof.CiteUncheckable, proof.CiteSourceNotHeld
			} else {
				res.Outcome, res.Reason = proof.DecideCount(c.Compare, c.N, observed[i], covered)
			}
		}
		out = append(out, res)
	}
	return out, events, nil
}

// attributesHold reports whether an event is the one an event-exists claim
// describes: its class, its source and its actor, each where stated, the
// actor compared without case as directories spell one person several ways.
func attributesHold(c Claim, e telemetry.Event) bool {
	if c.Class != 0 && e.Class != c.Class {
		return false
	}
	if c.EventSource != "" && e.Source != c.EventSource {
		return false
	}
	return c.Actor == "" || strings.EqualFold(e.Actor.Value, c.Actor) || strings.EqualFold(e.Actor.String(), c.Actor)
}

func all(ms []detect.Match, f map[string]string) bool {
	for _, m := range ms {
		if !m.Holds(f) {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
