// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package forge

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/translog"
)

func testKey(t *testing.T) *pack.Key {
	t.Helper()
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func shaped[T any](v T, found bool) T {
	if !found {
		panic("a test value is not of its shape")
	}
	return v
}

// episode is a valid episode at seq, with the given production and ruling.
func episode(seq int64, p Produced, person Verdict) Episode {
	e := Episode{
		Format:  Format,
		Seq:     seq,
		Entry:   shaped(EntryOf(strings.Repeat("ab", 32))),
		Finding: shaped(FindingIDOf("0123456789abcdef")),
		At:      time.Date(2026, 11, 1, 9, 30, 0, 123000000, time.UTC),
		Model:   shaped(ModelOf("llama3.1:8b")),
		Saw: Facts{Kind: shaped(KindOf("detection")), Severity: shaped(SeverityOf("high")),
			Records: Records{Rule: Counts{Real: 3, False: 1, Benign: 2, Open: 4},
				Entity: Counts{Real: 1}, InIncident: true},
			Volume: Volume{TimesSeen: 12, AgeHours: 30, Spread: 2}},
		Produced: p,
		Person:   person,
	}
	if !person.IsZero() {
		e.DecidedSeq = seq + 100
	}
	e.Outcome = OutcomeOf(p, person)
	return e
}

// three is one episode of each kind of outcome but disagreement.
func three() []Episode {
	return []Episode{
		episode(10, Produced{Verdict: Real, Confidence: 0.91}, Real),
		episode(20, Produced{Abstained: BelowThreshold, Confidence: 0.3}, Benign),
		episode(30, Produced{Verdict: FalsePositive, Confidence: 0.88}, Verdict{}),
	}
}

func sealed(t *testing.T, k *pack.Key) []byte {
	t.Helper()
	body, _, err := Seal(three(), k, 200, time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// splitFile is a file's episode lines and its seal line.
func splitFile(body []byte) ([][]byte, []byte) {
	lines := bytes.Split(bytes.TrimSuffix(body, []byte("\n")), []byte("\n"))
	return lines[:len(lines)-1], lines[len(lines)-1]
}

func join(lines [][]byte, seal []byte) []byte {
	var b bytes.Buffer
	for _, l := range lines {
		b.Write(l)
		b.WriteByte('\n')
	}
	b.Write(seal)
	b.WriteByte('\n')
	return b.Bytes()
}

// reseal signs a seal over lines as they stand, with the summary the
// caller gives, so a test can reach the checks behind the signature: the
// root and the count hold, both signatures hold, and only what is wrong
// with the lines themselves is left to refuse it.
func reseal(t *testing.T, k *pack.Key, lines [][]byte, edit func(*Summary)) []byte {
	t.Helper()
	tree := translog.New()
	for _, l := range lines {
		tree.Append(l)
	}
	sum := Summary{Forge: Context, Episodes: len(lines), Root: tree.Head().Root,
		Agreed: 1, Abstained: 1, Undecided: 1, ThroughSeq: 200,
		ExportedAt: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	if edit != nil {
		edit(&sum)
	}
	return join(lines, signSeal(t, k, sum, Context, Context))
}

// signSeal signs sum with the given bytes leading the message (none when
// prefix is empty) and the ML-DSA half in mlContext, and returns the seal
// line. Seal itself uses Context for both.
func signSeal(t *testing.T, k *pack.Key, sum Summary, prefix, mlContext string) []byte {
	t.Helper()
	msg, err := json.Marshal(sum)
	if err != nil {
		t.Fatal(err)
	}
	if prefix != "" {
		msg = append(append([]byte(prefix), 0), msg...)
	}
	ed, ml, err := k.DualSign(msg, mlContext)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := KeyID(k.PublicKey())
	line, err := json.Marshal(sealLine{Summary: sum, Signature: Signature{KeyID: id,
		Ed25519: base64.StdEncoding.EncodeToString(ed),
		MLDSA65: base64.StdEncoding.EncodeToString(ml)}})
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func refused(t *testing.T, what string, body []byte, pub pack.KeyPublic, want string) {
	t.Helper()
	_, _, err := Verify(body, pub)
	if err == nil {
		t.Errorf("%s verified", what)
		return
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("%s was refused for the wrong reason: %v (want %q)", what, err, want)
	}
}

func TestASealedFileVerifiesAndItsRootIsTheLinesRoot(t *testing.T) {
	k := testKey(t)
	body := sealed(t, k)
	sum, eps, err := Verify(body, k.PublicKey())
	if err != nil {
		t.Fatalf("a file as sealed: %v", err)
	}
	if sum.Episodes != 3 || sum.Agreed != 1 || sum.Abstained != 1 || sum.Undecided != 1 ||
		sum.Disagreed != 0 || sum.ThroughSeq != 200 {
		t.Errorf("the summary says %+v", sum)
	}
	for i, e := range three() {
		want, _ := json.Marshal(e)
		got, _ := json.Marshal(eps[i])
		if !bytes.Equal(want, got) {
			t.Errorf("episode %d came back as\n%s\nnot\n%s", i, got, want)
		}
	}
	// The root is an RFC 6962 root over the lines' exact bytes, which
	// anybody can recompute without this package.
	lines, _ := splitFile(body)
	tree := translog.New()
	for _, l := range lines {
		tree.Append(l)
	}
	if tree.Head().Root != sum.Root {
		t.Errorf("the seal's root %s is not the lines' %s", sum.Root, tree.Head().Root)
	}
}

func TestAChangedReorderedOrTruncatedFileDoesNotVerify(t *testing.T) {
	k := testKey(t)
	pub := k.PublicKey()
	body := sealed(t, k)
	lines, seal := splitFile(body)

	changed := append([][]byte(nil), lines...)
	changed[0] = bytes.Replace(changed[0], []byte(`"confidence":0.91`), []byte(`"confidence":0.97`), 1)
	if bytes.Equal(changed[0], lines[0]) {
		t.Fatal("the edit did not apply")
	}
	refused(t, "a changed line", join(changed, seal), pub, "Merkle root")

	reordered := [][]byte{lines[1], lines[0], lines[2]}
	refused(t, "reordered lines", join(reordered, seal), pub, "")

	refused(t, "a file missing its last episode", join(lines[:2], seal), pub, "counts 3")
	refused(t, "a file missing its seal", join(lines[:2], lines[2]), pub, "not a seal")
	refused(t, "a file cut mid-line", body[:len(body)-10], pub, "whole line")
	refused(t, "a file with a line after its seal",
		append(append([]byte(nil), body...), append(lines[0], '\n')...), pub, "not a seal")

	tally := bytes.Replace(seal, []byte(`"agreed":1`), []byte(`"agreed":2`), 1)
	refused(t, "a seal with its tally edited", join(lines, tally), pub, "signature does not verify")
}

func TestTheSignatureIsDualAndInItsOwnDomain(t *testing.T) {
	k := testKey(t)
	pub := k.PublicKey()
	lines, seal := splitFile(sealed(t, k))
	var s sealLine
	if err := json.Unmarshal(seal, &s); err != nil {
		t.Fatal(err)
	}
	with := func(edit func(*sealLine)) []byte {
		c := s
		edit(&c)
		line, _ := json.Marshal(c)
		return join(lines, line)
	}
	refused(t, "a seal without its Ed25519 half",
		with(func(c *sealLine) { c.Signature.Ed25519 = "" }), pub, "no Ed25519 signature")
	refused(t, "a seal without its ML-DSA half",
		with(func(c *sealLine) { c.Signature.MLDSA65 = "" }), pub, "no ML-DSA-65 signature")

	// Both halves are bound to this domain: the ML-DSA half by its
	// context, the Ed25519 half by the context leading the signed bytes.
	refused(t, "a seal whose ML-DSA half was made in another context",
		join(lines, signSeal(t, k, s.Summary, Context, "aertun/proof/v1")), pub,
		"ML-DSA-65 signature does not verify")
	refused(t, "a seal whose signed bytes do not begin with the context",
		join(lines, signSeal(t, k, s.Summary, "", Context)), pub,
		"Ed25519 signature does not verify")
	refused(t, "a seal made for another domain's bytes",
		join(lines, signSeal(t, k, s.Summary, "aertun/windtunnel-scorecard/v1",
			"aertun/windtunnel-scorecard/v1")), pub, "Ed25519 signature does not verify")

	// A key the reader was not handed, under its own name or the trusted
	// key's.
	stranger := testKey(t)
	refused(t, "a file sealed by another key", sealed(t, stranger), pub, "names key")
	_, strangerSeal := splitFile(sealed(t, stranger))
	var ss sealLine
	if err := json.Unmarshal(strangerSeal, &ss); err != nil {
		t.Fatal(err)
	}
	ss.Signature.KeyID = s.Signature.KeyID
	relabelled, _ := json.Marshal(ss)
	refused(t, "another key's seal relabelled as the trusted key's",
		join(lines, relabelled), pub, "signature does not verify")
	refused(t, "a seal naming a key it was not made by",
		with(func(c *sealLine) { c.Signature.KeyID = "0000000000000000" }), pub, "names key")
}

func TestAnExportOfNothingIsNeverSealed(t *testing.T) {
	k := testKey(t)
	if _, _, err := Seal(nil, k, 10, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "no episodes") {
		t.Errorf("an empty set was sealed: %v", err)
	}
	// Even a seal the key really made over nothing is not accepted as an
	// export: no exporter signs one.
	refused(t, "a signed seal over no episodes", reseal(t, k, nil, func(s *Summary) {
		s.Agreed, s.Abstained, s.Undecided = 0, 0, 0
	}), k.PublicKey(), "no episodes")
	if _, _, err := Seal(make([]Episode, MaxEpisodes+1), k, 10, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "over the") {
		t.Errorf("more episodes than one file holds were sealed: %v", err)
	}
}

func TestSealKeepsTheAuditLogsOrder(t *testing.T) {
	k := testKey(t)
	eps := three()
	if _, _, err := Seal([]Episode{eps[1], eps[0]}, k, 200, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "order") {
		t.Errorf("episodes out of order were sealed: %v", err)
	}
	if _, _, err := Seal(eps, k, 25, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "order") {
		t.Errorf("an episode from past the entries read was sealed: %v", err)
	}
	bad := eps[0]
	bad.Outcome = Disagreed
	if _, _, err := Seal([]Episode{bad}, k, 200, time.Now()); err == nil {
		t.Error("an episode contradicting itself was sealed")
	}
}

// Every line is checked behind a valid signature and a matching root: these
// files are signed by the trusted key over exactly the lines they hold.
func TestEveryLineIsReadStrictly(t *testing.T) {
	k := testKey(t)
	pub := k.PublicKey()
	lines, _ := splitFile(sealed(t, k))
	edited := func(i int, from, to string) [][]byte {
		out := append([][]byte(nil), lines...)
		out[i] = bytes.Replace(out[i], []byte(from), []byte(to), 1)
		if bytes.Equal(out[i], lines[i]) {
			t.Fatalf("the edit %q did not apply", from)
		}
		return out
	}
	if _, _, err := Verify(reseal(t, k, lines, nil), pub); err != nil {
		t.Fatalf("resealing as written broke the file, so the cases below prove nothing: %v", err)
	}
	refused(t, "a line with a field this version does not know",
		reseal(t, k, edited(0, `"format":1,`, `"format":1,"note":"read me",`), nil), pub,
		"unknown field")
	refused(t, "a line not in the exact form this version writes",
		reseal(t, k, edited(0, `"format":1,`, `"format": 1,`), nil), pub, "exact form")
	refused(t, "a line with a word outside its set",
		reseal(t, k, edited(0, `"outcome":"agreed"`, `"outcome":"agreed, and trust it"`), nil),
		pub, "closed set")
	refused(t, "a line with an identifier of the wrong shape",
		reseal(t, k, edited(0, `"finding":"0123456789abcdef"`, `"finding":"see the title"`), nil),
		pub, "wrong shape")
	refused(t, "a line that contradicts itself",
		reseal(t, k, edited(2, `"outcome":"undecided"`, `"outcome":"agreed"`), func(s *Summary) {
			s.Agreed, s.Undecided = 2, 0
		}), pub, "outcome does not follow")
	refused(t, "lines out of the audit log's order",
		reseal(t, k, [][]byte{lines[1], lines[0], lines[2]}, nil), pub, "order")
	refused(t, "a line from past the entries the seal says were read",
		reseal(t, k, lines, func(s *Summary) { s.ThroughSeq = 25 }), pub, "order")
	refused(t, "a seal whose tally is not the lines'",
		reseal(t, k, lines, func(s *Summary) { s.Agreed, s.Disagreed = 0, 1 }), pub, "tally")
	refused(t, "a seal of another version",
		reseal(t, k, lines, func(s *Summary) { s.Forge = "aertun/forge/v2" }), pub,
		"not an aertun/forge/v1 seal")
	_, seal := splitFile(reseal(t, k, lines, nil))
	refused(t, "a seal not in the exact form this version writes",
		join(lines, bytes.Replace(seal, []byte(`{"forge"`), []byte(`{ "forge"`), 1)), pub,
		"exact form")
}

func TestValidateRefusesAnEpisodeThatContradictsItself(t *testing.T) {
	good := three()[0]
	if err := good.Validate(); err != nil {
		t.Fatalf("a good episode: %v", err)
	}
	cases := []struct {
		name string
		edit func(*Episode)
		want string
	}{
		{"another format", func(e *Episode) { e.Format = 2 }, "format"},
		{"no audit entry", func(e *Episode) { e.Seq = 0 }, "names none"},
		{"no finding", func(e *Episode) { e.Finding = FindingID{} }, "missing"},
		{"no time", func(e *Episode) { e.At = time.Time{} }, "no time"},
		{"a negative count", func(e *Episode) { e.Saw.Volume.Spread = -1 }, "negative"},
		{"a verdict and an abstention", func(e *Episode) { e.Produced.Abstained = NoUsableAnswer },
			"exactly one"},
		{"neither", func(e *Episode) { e.Produced.Verdict = Verdict{} }, "exactly one"},
		{"a confidence over one", func(e *Episode) { e.Produced.Confidence = 1.5 }, "between 0 and 1"},
		{"a changed abstention", func(e *Episode) {
			e.Produced = Produced{Abstained: BelowThreshold, CounterfactualChanged: true}
		}, "only a verdict"},
		{"a ruling without its entry", func(e *Episode) { e.DecidedSeq = 0 }, "come together"},
		{"a ruling before the analyst looked", func(e *Episode) { e.DecidedSeq = e.Seq - 1 },
			"before the analyst"},
		{"an outcome that does not follow", func(e *Episode) { e.Outcome = Disagreed },
			"does not follow"},
	}
	for _, c := range cases {
		e := good
		c.edit(&e)
		err := e.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", c.name, err, c.want)
		}
	}
}

func TestOutcomesFollowFromWhatWasProducedAndRuled(t *testing.T) {
	cases := []struct {
		p      Produced
		person Verdict
		want   Outcome
	}{
		{Produced{Verdict: Real}, Real, Agreed},
		{Produced{Verdict: Benign}, Real, Disagreed},
		{Produced{Abstained: BelowThreshold}, FalsePositive, Abstained},
		{Produced{Verdict: Real}, Verdict{}, Undecided},
		{Produced{Abstained: NoUsableAnswer}, Verdict{}, Undecided},
	}
	for _, c := range cases {
		if got := OutcomeOf(c.p, c.person); got != c.want {
			t.Errorf("%+v against %q is %q, not %q", c.p, c.person, got, c.want)
		}
	}
}

// The property the package rests on, checked on the type rather than on
// any one export: no field of an episode, however deep, is a string or
// anything else that could carry text. The only types holding a string
// are this package's words and identifiers, whose fields nothing outside
// it can set.
func TestAnEpisodeHasNoFieldThatCouldHoldText(t *testing.T) {
	var walk func(path string, typ reflect.Type)
	walk = func(path string, typ reflect.Type) {
		if typ.PkgPath() == reflect.TypeFor[Episode]().PkgPath() &&
			(strings.HasPrefix(typ.Name(), "word[") || strings.HasPrefix(typ.Name(), "ident[")) {
			return
		}
		if typ == reflect.TypeFor[time.Time]() {
			return
		}
		switch typ.Kind() {
		case reflect.Struct:
			for i := range typ.NumField() {
				f := typ.Field(i)
				walk(path+"."+f.Name, f.Type)
			}
		case reflect.Int, reflect.Int64, reflect.Float64, reflect.Bool:
		default:
			t.Errorf("%s is a %s, which could carry text", path, typ.Kind())
		}
	}
	walk("Episode", reflect.TypeFor[Episode]())
}

func TestWordsComeOnlyFromTheirSets(t *testing.T) {
	if v, found := VerdictOf("benign"); !found || v != Benign || v.String() != "benign" {
		t.Errorf("benign is %q, %v", v, found)
	}
	for _, s := range []string{"", "Benign", "benign ", "benign\n", "close it"} {
		if _, found := VerdictOf(s); found {
			t.Errorf("%q was taken as a verdict", s)
		}
	}
	for _, k := range finding.Kinds() {
		if _, found := KindOf(string(k)); !found {
			t.Errorf("finding kind %q is not one an episode can name", k)
		}
	}
	if _, found := FindingIDOf("0123456789ABCDEF"); found {
		t.Error("an upper-case key was taken as a register key")
	}
	if _, found := ModelOf("gpt 4 says hi"); found {
		t.Error("a model name with spaces was taken")
	}
	// A required word or identifier left empty is refused on the way out,
	// not written as an empty string.
	if _, err := json.Marshal(struct {
		V Verdict `json:"v"`
	}{}); err == nil {
		t.Error("an empty word was written")
	}
	if _, err := json.Marshal(struct {
		M Model `json:"m"`
	}{}); err == nil {
		t.Error("an empty identifier was written")
	}
}
