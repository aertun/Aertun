// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/aertun/aertun/internal/jcs"
	"github.com/aertun/aertun/internal/stats"
	"github.com/aertun/aertun/internal/telemetry"
)

// Mutation mode: the same attack, spelled differently, replayed again.
//
// A rule that matches the bytes one scenario happened to emit has been shown
// to catch that spelling, not the attack. The attacker chooses the spelling
// of everything they type — the URL a tool posts to, the path it writes, the
// command line a shell runs — and every one of those has many spellings its
// consumer treats as the same thing. A run under mutation replays each
// scenario's session again with those fields respelled, and reports how
// many of the respelled sessions the instrument missed.
//
// # What makes a respelling effect-preserving
//
// Each field is respelled only within an equivalence its consumer applies,
// written down where it is defined:
//
//   - URLs (RFC 9110 section 4.2.3, http(s) normalisation, and RFC 3986
//     section 6.2.2.3, dot-segment removal): the default port written out
//     or left empty, an unreserved letter or digit percent-encoded in
//     either hex case, a "./" segment inserted, an empty path written as
//     "/", and the scheme's and host's letter case. Case is never the whole
//     change: a respelling that differs from the original only in case is
//     refused, because this engine's comparisons fold case and a variant a
//     case-folding rule cannot tell apart from the original tests nothing.
//   - Paths an agent passes to a tool (POSIX.1-2024 Base Definitions
//     section 4.16, pathname resolution): a "." component inserted, and a
//     non-leading slash doubled. A leading slash is never doubled, because
//     a pathname that begins with exactly two slashes is
//     implementation-defined, and nothing is added after the last
//     component, because a trailing slash demands a directory.
//   - Shell command lines (POSIX.1-2024 Shell Command Language section 2.2,
//     quoting, and 2.6.7, quote removal): a character escaped with a
//     backslash or put inside single or double quotes, empty quotes inserted
//     inside a word, runs of blanks between words and around the line, and
//     the path forms above in a command word that names its program by a
//     path. The shell removes every one of those before the program runs, so
//     the program receives the same arguments.
//
// # What is never respelled
//
// Only fields whose spelling the actor chooses. A tool's name, an
// operation, a label the ingest boundary stamped, a trace id, a path a
// recorder reports — the attacker types none of those, and respelling them
// would measure an evasion nobody can perform. So the table below is
// closed, per source, and a field outside it is copied byte for byte into
// every variant. Within a field, a value outside the shape the equivalences
// are proven for — a URL with userinfo or a fragment, a command line with an
// expansion, a pipe, a redirection, a glob, or a reserved word — is not
// respelled at all rather than respelled approximately.
//
// Three respellings a reader might expect are deliberately absent. Changing
// option order or inserting an environment variable changes what the
// program or the shell receives unless the program's parser or the shell's
// environment says otherwise, and neither is in the event, so neither is
// provably effect-preserving. Reordering or padding an event's fields is a
// no-op in this engine: events are maps matched by field name, so a
// reordered record is the same record, and an added field is either read by
// no rule or read by an exists test, where it is a change of meaning rather
// than of spelling. And cmd.exe's caret is absent because no scenario
// declares a Windows shell and no cmd.exe is available to test the
// equivalence against.
//
// One caveat goes with the shell grammar: quoting a command word stops a
// shell expanding an alias of that name. The agent tools these scenarios
// model run their commands non-interactively, where no alias is defined.
//
// # Determinism
//
// A variant is a pure function of the scenario id, the variant number and
// the placed session: the randomness is SHA-256 in counter mode over a
// domain string, the id and the number, so the same inputs produce the same
// bytes on every machine and a variant a scorecard counted can be rebuilt
// and inspected. Variants of one scenario are pairwise distinct and never
// the original; when the grammar runs out of distinct spellings the run
// says so and makes fewer, rather than counting one respelling twice.

// MaxMutate is the most variants a run makes of one scenario: enough to
// see a rule's failure modes, few enough that a run stays a CI step.
const MaxMutate = 64

// The respelling grammars, a closed set.
const (
	SurfaceURL   = "url"
	SurfacePath  = "posix-path"
	SurfaceShell = "posix-sh"
)

// actorSpelled is the closed table of fields whose spelling the actor
// chooses, per source. otel/genai tool calls carry the agent's own
// arguments; every other source in the corpus spells its fields itself —
// collector/watch reports the path it watched, not the path somebody typed.
var actorSpelled = map[string]map[string]string{
	"otel/genai": {
		"url":     SurfaceURL,
		"dest":    SurfaceURL,
		"path":    SurfacePath,
		"command": SurfaceShell,
	},
}

// posixShells are the raw.shell values whose quoting the posix-sh grammar
// models. A command line without one of these beside it is not respelled:
// the same characters mean different things to cmd.exe or PowerShell.
var posixShells = map[string]bool{"sh": true, "bash": true, "dash": true}

// mutationCaveat is stated on every document that carries a mutation
// section, in the blind tradition.
const mutationCaveat = "Variants are respellings of a few scenarios, not " +
	"independent attacks: the Wilson bounds treat each variant as a trial, " +
	"which overstates the evidence when one scenario's variants succeed or " +
	"fail together. Only fields whose spelling the actor chooses are " +
	"respelled, and only by equivalences the consumer applies; a scenario " +
	"with no such field makes no variants and is named, not counted."

// mutantsDir is where a run writes its variants' scratch spools, beneath
// the scratch root. The underscore is a character sanitize never produces,
// so no scenario's own spool can share the name.
const mutantsDir = "_mutants"

// MutationRow is one scenario under mutation.
type MutationRow struct {
	Scenario string `json:"scenario"`
	// Original is the scenario's tier unmutated: the row above it.
	Original string `json:"original_outcome"`
	// Surface names the raw fields that were respelled, sorted. Empty when
	// nothing in the session is spelled by its actor.
	Surface []string `json:"surface,omitempty"`
	// Variants is how many distinct variants were made and replayed.
	Variants      int `json:"variants"`
	Caught        int `json:"caught_alert"`
	Missed        int `json:"missed"`
	TelemetryOnly int `json:"caught_telemetry_only"`
	WronglyQuiet  int `json:"wrongly_quiet"`
	// Digest is sha256 over the RFC 8785 form of every variant's events,
	// so a reader who rebuilds the variants can prove they are the ones
	// that were scored.
	Digest string `json:"digest,omitempty"`
	Note   string `json:"note,omitempty"`
}

// RateBound is a rate with the exact counts behind it and its 95% Wilson
// interval: k of n, never the rate alone.
type RateBound struct {
	K    int     `json:"k"`
	N    int     `json:"n"`
	Rate float64 `json:"rate"`
	Low  float64 `json:"wilson_low"`
	High float64 `json:"wilson_high"`
}

func bound(k, n int) *RateBound {
	lo, hi := stats.Wilson(k, n)
	return &RateBound{K: k, N: n, Rate: rate(k, n), Low: lo, High: hi}
}

// MutationReport is the run under mutation.
type MutationReport struct {
	// Requested is the variants asked for per scenario.
	Requested int           `json:"requested"`
	Rows      []MutationRow `json:"rows"`
	// MissUnderMutation is missed variants over the variants of must-alert
	// scenarios that landed caught or missed — the primary aggregate's
	// rule, applied to variants. Absent when no such variant was made: a
	// rate over nothing is not printed.
	MissUnderMutation *RateBound `json:"miss_under_mutation,omitempty"`
	// Evasion is the same count restricted to scenarios the instrument
	// caught unmutated: how often respelling alone turned a catch into a
	// miss.
	Evasion *RateBound `json:"evasion,omitempty"`
	Caveat  string     `json:"caveat"`
}

// tally folds the rows into the two rates. Scenarios that carry no
// must-alert expectation are precision claims and stay out of both, as
// they stay out of the primary miss rate.
func (m *MutationReport) tally() {
	sort.Slice(m.Rows, func(i, j int) bool {
		return m.Rows[i].Scenario < m.Rows[j].Scenario
	})
	var k, n, ek, en int
	for _, r := range m.Rows {
		if r.Original != OutcomeCaughtAlert && r.Original != OutcomeMissed {
			continue
		}
		k += r.Missed
		n += r.Caught + r.Missed
		if r.Original == OutcomeCaughtAlert {
			ek += r.Missed
			en += r.Caught + r.Missed
		}
	}
	if n > 0 {
		m.MissUnderMutation = bound(k, n)
	}
	if en > 0 {
		m.Evasion = bound(ek, en)
	}
}

// mutRand is the deterministic randomness behind one variant: SHA-256 in
// counter mode over a domain string, the scenario id, the variant number
// and the attempt. Nothing else feeds it — no clock, no process state.
type mutRand struct {
	seed  [32]byte
	block [32]byte
	used  int
	ctr   uint64
}

func newMutRand(id string, variant, attempt int) *mutRand {
	h := sha256.New()
	h.Write([]byte("aertun/windtunnel-mutation/v1"))
	h.Write([]byte{0})
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write([]byte(strconv.Itoa(variant)))
	h.Write([]byte{0})
	h.Write([]byte(strconv.Itoa(attempt)))
	r := &mutRand{used: 32}
	copy(r.seed[:], h.Sum(nil))
	return r
}

func (r *mutRand) next() byte {
	if r.used == len(r.block) {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], r.ctr)
		r.block = sha256.Sum256(append(r.seed[:], c[:]...))
		r.ctr++
		r.used = 0
	}
	b := r.block[r.used]
	r.used++
	return b
}

// intn is a draw in [0, n) for the small n this file uses.
func (r *mutRand) intn(n int) int {
	return (int(r.next())<<8 | int(r.next())) % n
}

func (r *mutRand) coin() bool { return r.next()&1 == 1 }

// surfaceOf is the grammar one raw field of one event is respelled by, or
// "" when its actor does not spell it or its value lies outside the shape
// the grammar's equivalences are proven for.
func surfaceOf(e telemetry.Event, field string) string {
	g := actorSpelled[e.Source][field]
	v, ok := e.Raw[field]
	if !ok {
		return ""
	}
	switch g {
	case SurfaceURL:
		if _, ok := parseHTTPURL(v); ok {
			return g
		}
	case SurfacePath:
		if pathRespellable(v) {
			return g
		}
	case SurfaceShell:
		if !posixShells[e.Raw["shell"]] {
			return ""
		}
		if _, err := shellWords(v); err == nil {
			return g
		}
	}
	return ""
}

// respellableFields is an event's respellable raw fields, sorted, so the
// draws are taken in the same order on every machine.
func respellableFields(e telemetry.Event) []string {
	var out []string
	for f := range e.Raw {
		if surfaceOf(e, f) != "" {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// respellAttempts bounds the retries for one field and for one variant: a
// draw can land on a case-only respelling, or on a variant already made.
const respellAttempts = 16

// respell is one field respelled by its grammar, or false when no attempt
// produced a respelling that differs from the original beyond letter case.
func respell(grammar, v string, r *mutRand) (string, bool) {
	for i := 0; i < respellAttempts; i++ {
		var out string
		switch grammar {
		case SurfaceURL:
			out = respellURL(v, r)
		case SurfacePath:
			out = respellPath(v, r)
		case SurfaceShell:
			out = respellShell(v, r)
		}
		// The guard the rejected attempt lacked: a respelling equal to
		// the original under case folding is no respelling to a rule that
		// folds case, which every comparison in this engine does.
		if out != "" && !strings.EqualFold(out, v) {
			return out, true
		}
	}
	return "", false
}

// mutateSession makes up to n distinct effect-preserving variants of one
// placed session, and names the raw fields it respelled. A session with
// nothing its actor spells makes none.
func mutateSession(id string, events []telemetry.Event, n int) (
	[][]telemetry.Event, []string) {

	fields := make([][]string, len(events))
	names := map[string]bool{}
	for i, e := range events {
		fields[i] = respellableFields(e)
		for _, f := range fields[i] {
			names["raw."+f] = true
		}
	}
	surface := make([]string, 0, len(names))
	for f := range names {
		surface = append(surface, f)
	}
	sort.Strings(surface)

	// The original is seen before any variant is made, so no variant can
	// be the original under another name: a "variant" that changed
	// nothing would be counted as a trial of an evasion nobody attempted.
	seen := map[string]bool{sessionKey(events): true}
	var out [][]telemetry.Event
	for v := 1; v <= n; v++ {
		made := false
		for attempt := 0; attempt < respellAttempts; attempt++ {
			cand, ok := respellSession(events, fields,
				newMutRand(id, v, attempt))
			if !ok {
				continue
			}
			key := sessionKey(cand)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, cand)
			made = true
			break
		}
		if !made {
			// The grammar has run out of distinct spellings for this
			// session; the row reports how many it found.
			break
		}
	}
	return out, surface
}

// respellSession copies a session with every respellable field respelled.
// Every one of them changes in every variant, beyond case, or the attempt
// is discarded.
func respellSession(events []telemetry.Event, fields [][]string,
	r *mutRand) ([]telemetry.Event, bool) {

	out := make([]telemetry.Event, len(events))
	for i, e := range events {
		c := e
		if len(e.Raw) > 0 {
			c.Raw = make(map[string]string, len(e.Raw))
			for k, v := range e.Raw {
				c.Raw[k] = v
			}
		}
		for _, f := range fields[i] {
			nv, ok := respell(surfaceOf(e, f), e.Raw[f], r)
			if !ok {
				return nil, false
			}
			c.Raw[f] = nv
		}
		out[i] = c
	}
	return out, true
}

// sessionKey identifies a session by every raw value it carries, in event
// order and key order, with separators no value can contain unescaped.
func sessionKey(events []telemetry.Event) string {
	var b strings.Builder
	for _, e := range events {
		keys := make([]string, 0, len(e.Raw))
		for k := range e.Raw {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(strconv.Quote(k))
			b.WriteByte('=')
			b.WriteString(strconv.Quote(e.Raw[k]))
			b.WriteByte(0)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// variantsDigest is sha256 over the RFC 8785 form of every variant.
func variantsDigest(variants [][]telemetry.Event) (string, error) {
	b, err := jcs.Marshal(variants)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// runVariants replays a scenario's respelled sessions over the base
// stream, each into its own scratch spool, and scores each exactly as the
// unmutated session was scored.
func runVariants(l *Loaded, ref *Reference, base []telemetry.Event,
	into string, placed *Placed, ambient *passResult, their bool,
	original string, n int) (*MutationRow, error) {

	sc := l.Scenario
	variants, surface := mutateSession(sc.ID, placed.Events, n)
	row := &MutationRow{Scenario: sc.ID, Original: original,
		Surface: surface, Variants: len(variants)}
	switch {
	case len(surface) == 0:
		row.Note = "nothing in this session is spelled by its actor — " +
			"its fields are identifiers the instrumentation stamps or " +
			"paths a recorder reports — so no respelling is an evasion " +
			"anyone could make, and no variant is counted"
		return row, nil
	case len(variants) < n:
		row.Note = fmt.Sprintf("the grammar holds only %d distinct "+
			"spelling(s) of this session beyond the original; asking for "+
			"%d would count one respelling twice", len(variants), n)
	}
	digest, err := variantsDigest(variants)
	if err != nil {
		return nil, err
	}
	row.Digest = digest
	for i, events := range variants {
		dir := filepath.Join(into, mutantsDir,
			fmt.Sprintf("%s--%02d", sanitize(sc.ID), i+1))
		res, err := replaySession(base, events, ref, dir)
		if err != nil {
			return nil, fmt.Errorf("%s, variant %d: %w", sc.ID, i+1, err)
		}
		vp := &Placed{Events: events, Anchor: placed.Anchor,
			Delays: placed.Delays}
		switch sessionOutcome(sc, ref, res, ambient, vp, their) {
		case OutcomeCaughtAlert:
			row.Caught++
		case OutcomeMissed:
			row.Missed++
		case OutcomeCaughtTelemetry:
			row.TelemetryOnly++
		case OutcomeWronglyQuiet:
			row.WronglyQuiet++
		}
	}
	return row, nil
}

// httpURL is an absolute http(s) URL split into the parts the respelling
// touches, each as written.
type httpURL struct {
	scheme, host, port, path, query string
	hasPort, hasQuery               bool
}

// parseHTTPURL accepts the closed shape the URL equivalences are proven
// for: http or https, a host of letters, digits, dots and hyphens, an
// optional numeric port, a path of unreserved characters, slashes and
// percent-encodings, and an optional query that is carried untouched. No
// userinfo and no fragment.
func parseHTTPURL(v string) (httpURL, bool) {
	var u httpURL
	scheme, rest, ok := strings.Cut(v, "://")
	if !ok {
		return u, false
	}
	switch strings.ToLower(scheme) {
	case "http", "https":
	default:
		return u, false
	}
	u.scheme = scheme
	end := strings.IndexAny(rest, "/?")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	host, port, hasPort := strings.Cut(authority, ":")
	if host == "" {
		return u, false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if !(isAlnum(c) || c == '.' || c == '-') {
			return u, false
		}
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return u, false
		}
	}
	u.host, u.port, u.hasPort = host, port, hasPort
	path, query, hasQuery := strings.Cut(tail, "?")
	if path != "" && path[0] != '/' {
		return u, false
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case isAlnum(c), strings.IndexByte("-._~/", c) >= 0:
		case c == '%' && i+2 < len(path) && isHex(path[i+1]) &&
			isHex(path[i+2]):
			i += 2
		default:
			return u, false
		}
	}
	for i := 0; i < len(query); i++ {
		if query[i] <= ' ' || query[i] > '~' || query[i] == '#' {
			return u, false
		}
	}
	u.path, u.query, u.hasQuery = path, query, hasQuery
	return u, true
}

func (u httpURL) String() string {
	var b strings.Builder
	b.WriteString(u.scheme)
	b.WriteString("://")
	b.WriteString(u.host)
	if u.hasPort {
		b.WriteByte(':')
		b.WriteString(u.port)
	}
	b.WriteString(u.path)
	if u.hasQuery {
		b.WriteByte('?')
		b.WriteString(u.query)
	}
	return b.String()
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// respellURL applies a random non-empty set of the URL equivalences.
func respellURL(v string, r *mutRand) string {
	u, ok := parseHTTPURL(v)
	if !ok {
		return ""
	}
	type op func()
	var ops []op
	if !u.hasPort {
		ops = append(ops, func() {
			// RFC 9110 section 4.2.3: a port equal to the scheme's default
			// is the same as none; RFC 3986 section 6.2.3: so is an empty
			// one.
			u.hasPort = true
			if r.coin() {
				return
			}
			u.port = "443"
			if strings.EqualFold(u.scheme, "http") {
				u.port = "80"
			}
		})
	}
	if pctCandidates(u.path) != nil {
		ops = append(ops, func() {
			// An unreserved character and its percent-encoding are the
			// same character (RFC 9110 section 4.2.3), in either hex case
			// (RFC 3986 section 6.2.2.1). Letters and digits only: an
			// encoded dot could be read as a dot-segment by a normaliser
			// that decodes after removing them.
			for k := 1 + r.intn(2); k > 0; k-- {
				c := pctCandidates(u.path)
				if c == nil {
					break
				}
				i := c[r.intn(len(c))]
				enc := fmt.Sprintf("%%%02X", u.path[i])
				if r.coin() {
					enc = strings.ToLower(enc)
				}
				u.path = u.path[:i] + enc + u.path[i+1:]
			}
		})
	}
	if u.path == "" {
		// An empty path is "/" (RFC 9110 section 4.2.3).
		ops = append(ops, func() { u.path = "/" })
	} else {
		ops = append(ops, func() {
			// A "." segment is removed by reference resolution (RFC 3986
			// section 6.2.2.3).
			slashes := indexesOf(u.path, '/')
			i := slashes[r.intn(len(slashes))]
			u.path = u.path[:i+1] + "./" + u.path[i+1:]
		})
	}
	ops = append(ops, func() {
		// Scheme and host are case-insensitive (RFC 3986 section
		// 6.2.2.1). Never the whole change: respell refuses a result equal
		// to the original under case folding.
		u.scheme = flipSomeCase(u.scheme, r)
		u.host = flipSomeCase(u.host, r)
	})
	chosen := false
	for _, f := range ops {
		if r.coin() {
			f()
			chosen = true
		}
	}
	if !chosen {
		ops[r.intn(len(ops))]()
	}
	return u.String()
}

// pctCandidates are the positions of path letters and digits that are not
// already inside a percent-encoding.
func pctCandidates(path string) []int {
	var out []int
	for i := 0; i < len(path); i++ {
		if path[i] == '%' {
			i += 2
			continue
		}
		if isAlnum(path[i]) {
			out = append(out, i)
		}
	}
	return out
}

func indexesOf(s string, c byte) []int {
	var out []int
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			out = append(out, i)
		}
	}
	return out
}

// flipSomeCase flips the case of a random non-empty subset of the letters.
func flipSomeCase(s string, r *mutRand) string {
	b := []byte(s)
	var letters []int
	for i, c := range b {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			letters = append(letters, i)
		}
	}
	if len(letters) == 0 {
		return s
	}
	flipped := false
	for _, i := range letters {
		if r.coin() {
			b[i] ^= 0x20
			flipped = true
		}
	}
	if !flipped {
		b[letters[r.intn(len(letters))]] ^= 0x20
	}
	return string(b)
}

// pathRespellable is the shape the path equivalences are proven for: not
// empty, no NUL or control character, and not beginning with two slashes,
// whose meaning POSIX leaves to the implementation.
func pathRespellable(v string) bool {
	if v == "" || strings.HasPrefix(v, "//") || !utf8.ValidString(v) {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < ' ' {
			return false
		}
	}
	return true
}

// respellPath applies a random non-empty set of the path equivalences,
// each at a point before the last component.
func respellPath(v string, r *mutRand) string {
	if !pathRespellable(v) {
		return ""
	}
	// interior is every slash that has a component after it.
	interior := func(p string) []int {
		var out []int
		for _, i := range indexesOf(p, '/') {
			if i < len(p)-1 {
				out = append(out, i)
			}
		}
		return out
	}
	dot := func(p string) string {
		// "." names the directory it is in (POSIX pathname resolution).
		at := interior(p)
		if !strings.HasPrefix(p, "/") {
			at = append([]int{-1}, at...) // "./" before a relative path
		}
		if len(at) == 0 {
			return p
		}
		i := at[r.intn(len(at))]
		return p[:i+1] + "./" + p[i+1:]
	}
	double := func(p string) string {
		// Successive slashes are one slash, except exactly two leading.
		var at []int
		for _, i := range interior(p) {
			if i > 0 {
				at = append(at, i)
			}
		}
		if len(at) == 0 {
			return p
		}
		i := at[r.intn(len(at))]
		return p[:i] + "/" + p[i:]
	}
	out := v
	chosen := false
	for _, f := range []func(string) string{dot, double} {
		if r.coin() {
			out = f(out)
			chosen = true
		}
	}
	if !chosen {
		out = dot(out)
	}
	return out
}

// safePlain is the characters that stand for themselves unquoted in every
// position the respelling puts them: POSIX lists | & ; < > ( ) $ ` \ " '
// and the blanks as always special, and * ? [ ] ^ - ! # ~ = % { , } as
// special under certain circumstances, of which only the hyphen is in the
// portable filename character set and safe.
func safePlain(c rune) bool {
	return c < utf8.RuneSelf && (isAlnum(byte(c)) ||
		strings.IndexByte("_./:@+-", byte(c)) >= 0)
}

// doubleQuotable is what keeps its literal value inside double quotes:
// everything but $ ` \ and " (POSIX section 2.2.3), and not !, which
// bash's history expansion reads there when it is interactive.
func doubleQuotable(c rune) bool {
	return c != '$' && c != '`' && c != '\\' && c != '"' && c != '!'
}

// reservedWords are recognised only unquoted and only as a command word,
// so a command whose first word is one of them is not a simple command
// and quoting it would change what it is.
var reservedWords = map[string]bool{
	"!": true, "{": true, "}": true, "case": true, "do": true, "done": true,
	"elif": true, "else": true, "esac": true, "fi": true, "for": true,
	"if": true, "in": true, "then": true, "until": true, "while": true,
	"[[": true, "]]": true, "function": true, "select": true, "time": true,
}

// shellWords splits a command line in the closed subset into the words the
// shell passes to the program: blanks separate words; an unquoted
// character must be one that stands for itself or be escaped with a
// backslash; single quotes keep everything up to the next single quote;
// double quotes keep everything that keeps its literal value inside them.
// Anything else — an expansion, an operator, a glob, a newline, an
// assignment or a reserved word in command position — is refused, because
// the respelling's equivalences are proven only for this subset.
func shellWords(s string) ([]string, error) {
	if !utf8.ValidString(s) {
		return nil, fmt.Errorf("the command line is not valid UTF-8")
	}
	rs := []rune(s)
	for _, c := range rs {
		if c < ' ' && c != '\t' {
			return nil, fmt.Errorf("the command line carries a control " +
				"character, which the subset does not include")
		}
	}
	var words []string
	var cur strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == ' ' || c == '\t':
			flush()
		case c == '\\':
			if i+1 >= len(rs) {
				return nil, fmt.Errorf("the command line ends in a backslash")
			}
			i++
			cur.WriteRune(rs[i])
			inWord = true
		case c == '\'':
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				j++
			}
			if j >= len(rs) {
				return nil, fmt.Errorf("a single quote never closes")
			}
			cur.WriteString(string(rs[i+1 : j]))
			i = j
			inWord = true
		case c == '"':
			j := i + 1
			for j < len(rs) && rs[j] != '"' {
				if !doubleQuotable(rs[j]) {
					return nil, fmt.Errorf("%q inside double quotes is "+
						"outside the subset", rs[j])
				}
				j++
			}
			if j >= len(rs) {
				return nil, fmt.Errorf("a double quote never closes")
			}
			cur.WriteString(string(rs[i+1 : j]))
			i = j
			inWord = true
		case safePlain(c):
			cur.WriteRune(c)
			inWord = true
		default:
			return nil, fmt.Errorf("%q unquoted is outside the subset", c)
		}
	}
	flush()
	if len(words) == 0 || words[0] == "" {
		return nil, fmt.Errorf("the command line names no command")
	}
	if strings.ContainsRune(words[0], '=') || reservedWords[words[0]] {
		return nil, fmt.Errorf("the first word %q is an assignment or a "+
			"reserved word, not a command name", words[0])
	}
	return words, nil
}

// blanks are the separators a respelling draws from: runs of spaces and
// tabs, which the shell treats as one separator.
var blanks = []string{" ", "  ", "\t", " \t", "   "}

// respellShell renders the command's words again, each character in a
// form the shell reads as itself, with the separators and the command
// word's path drawn afresh.
func respellShell(v string, r *mutRand) string {
	words, err := shellWords(v)
	if err != nil {
		return ""
	}
	var b strings.Builder
	if r.intn(4) == 0 {
		b.WriteString(blanks[r.intn(len(blanks))])
	}
	for i, w := range words {
		if i > 0 {
			b.WriteString(blanks[r.intn(len(blanks))])
		}
		if i == 0 && strings.Contains(w, "/") && r.coin() {
			// A command word with a slash is a path the kernel resolves;
			// a bare name is looked up in PATH and is never given one.
			if p := respellPath(w, r); p != "" {
				w = p
			}
		}
		b.WriteString(renderWord(w, r))
	}
	if r.intn(4) == 0 {
		b.WriteString(blanks[r.intn(len(blanks))])
	}
	return b.String()
}

// renderWord writes one word so that quote removal gives it back: each
// character plain, backslash-escaped, or inside single or double quotes,
// with empty quotes sometimes inserted between characters.
func renderWord(w string, r *mutRand) string {
	if w == "" {
		if r.coin() {
			return "''"
		}
		return `""`
	}
	var b strings.Builder
	var open rune
	closeQuote := func() {
		if open != 0 {
			b.WriteRune(open)
			open = 0
		}
	}
	for i, c := range w {
		if i > 0 && r.intn(12) == 0 {
			closeQuote()
			if r.coin() {
				b.WriteString("''")
			} else {
				b.WriteString(`""`)
			}
		}
		switch style := pickStyle(c, r); style {
		case 'p':
			closeQuote()
			b.WriteRune(c)
		case '\\':
			closeQuote()
			b.WriteByte('\\')
			b.WriteRune(c)
		default:
			if open != style {
				closeQuote()
				b.WriteRune(style)
				open = style
			}
			b.WriteRune(c)
		}
	}
	closeQuote()
	return b.String()
}

// pickStyle draws how one character is written, from the forms that keep
// its literal value: plain only when it stands for itself, a backslash
// only before ASCII, single quotes for anything but a single quote, double
// quotes for what keeps its value inside them.
func pickStyle(c rune, r *mutRand) rune {
	var forms []rune
	if safePlain(c) {
		// Mostly plain, as a person obfuscating by hand writes: a few
		// quoted or escaped characters in an otherwise readable line.
		for i := 0; i < 12; i++ {
			forms = append(forms, 'p')
		}
	}
	if c < utf8.RuneSelf {
		forms = append(forms, '\\')
	}
	if c != '\'' {
		forms = append(forms, '\'')
	}
	if doubleQuotable(c) {
		forms = append(forms, '"')
	}
	return forms[r.intn(len(forms))]
}
