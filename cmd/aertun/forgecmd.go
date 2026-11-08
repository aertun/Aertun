// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/analyst"
	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/forge"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

// The forge: the analyst's past work, as signed training episodes.
//
// `forge export` reads this store's audit log and pairs each of the
// analyst's records — a suggestion, or an abstention — with the last ruling
// a verified person recorded on that finding afterwards. Each pair becomes
// an internal/forge episode: the facts the model was shown, read from the
// counts the analyst recorded beside its answer rather than rebuilt; what
// it answered; and how that compares with the ruling. The file is signed
// with a key the caller names, and its Merkle root is written to the audit
// log before the file is, so no export leaves the store unrecorded.
//
// `forge verify` checks a file against a public key, offline, and with
// --log also finds the record of the export in this store's audit log,
// whose chain has to hold first.
//
// Neither ever reads the text the analyst was shown beside the counts.
// What gets into an episode is decided by internal/forge's types, which
// have no field that could hold it.

// forgeExportedAction records an export: its root, its size, its signer.
const forgeExportedAction = "forge.exported"

func cmdForge(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("forge needs export or verify")
	}
	switch args[0] {
	case "export":
		return forgeExport(root, args[1:])
	case "verify":
		return forgeVerify(root, args[1:])
	default:
		return fmt.Errorf("unknown forge command %q; try export or verify", args[0])
	}
}

// ---- what the analyst saw, as it records it --------------------------------

// sawInts and sawBools are the counted facts the analyst records under
// "saw_" keys beside each answer, with where each lives in what the model
// was shown and in an episode. One table for both directions, so the
// record and the reader of it cannot drift apart.
var sawInts = []struct {
	key  string
	from func(*analyst.Facts) *int
	into func(*forge.Facts) *int
}{
	{"saw_rule_real", func(f *analyst.Facts) *int { return &f.Records.Rule.Real },
		func(f *forge.Facts) *int { return &f.Records.Rule.Real }},
	{"saw_rule_false_positive", func(f *analyst.Facts) *int { return &f.Records.Rule.False },
		func(f *forge.Facts) *int { return &f.Records.Rule.False }},
	{"saw_rule_benign", func(f *analyst.Facts) *int { return &f.Records.Rule.Benign },
		func(f *forge.Facts) *int { return &f.Records.Rule.Benign }},
	{"saw_rule_undecided", func(f *analyst.Facts) *int { return &f.Records.Rule.Open },
		func(f *forge.Facts) *int { return &f.Records.Rule.Open }},
	{"saw_entity_real", func(f *analyst.Facts) *int { return &f.Records.Entity.Real },
		func(f *forge.Facts) *int { return &f.Records.Entity.Real }},
	{"saw_entity_false_positive", func(f *analyst.Facts) *int { return &f.Records.Entity.False },
		func(f *forge.Facts) *int { return &f.Records.Entity.False }},
	{"saw_entity_benign", func(f *analyst.Facts) *int { return &f.Records.Entity.Benign },
		func(f *forge.Facts) *int { return &f.Records.Entity.Benign }},
	{"saw_entity_undecided", func(f *analyst.Facts) *int { return &f.Records.Entity.Open },
		func(f *forge.Facts) *int { return &f.Records.Entity.Open }},
	{"saw_times_seen", func(f *analyst.Facts) *int { return &f.Volume.TimesSeen },
		func(f *forge.Facts) *int { return &f.Volume.TimesSeen }},
	{"saw_age_hours", func(f *analyst.Facts) *int { return &f.Volume.AgeHours },
		func(f *forge.Facts) *int { return &f.Volume.AgeHours }},
	{"saw_other_entities_open", func(f *analyst.Facts) *int { return &f.Volume.Spread },
		func(f *forge.Facts) *int { return &f.Volume.Spread }},
	{"saw_indicator_sources", func(f *analyst.Facts) *int { return &f.Volume.Sources },
		func(f *forge.Facts) *int { return &f.Volume.Sources }},
}

var sawBools = []struct {
	key  string
	from func(*analyst.Facts) *bool
	into func(*forge.Facts) *bool
}{
	{"saw_from_indicator", func(f *analyst.Facts) *bool { return &f.Indicator },
		func(f *forge.Facts) *bool { return &f.Indicator }},
	{"saw_rule_on_trial", func(f *analyst.Facts) *bool { return &f.Trial },
		func(f *forge.Facts) *bool { return &f.Trial }},
	{"saw_in_an_incident", func(f *analyst.Facts) *bool { return &f.Records.InIncident },
		func(f *forge.Facts) *bool { return &f.Records.InIncident }},
}

// sawDetail is what the model was shown as counted facts, as audit detail
// for the analyst's record: numbers, booleans, and the kind and severity
// as words of internal/forge's closed sets. A kind or severity outside
// those sets is left out rather than copied — the record then cannot be
// exported, and nothing a register file says reaches the log through here.
// The text the model read beside the facts is not in it.
func sawDetail(f analyst.Facts) map[string]string {
	d := map[string]string{}
	if k, ok := forge.KindOf(f.Kind); ok {
		d["saw_kind"] = k.String()
	}
	if s, ok := forge.SeverityOf(f.Severity); ok {
		d["saw_severity"] = s.String()
	}
	for _, c := range sawInts {
		d[c.key] = strconv.Itoa(*c.from(&f))
	}
	for _, c := range sawBools {
		d[c.key] = strconv.FormatBool(*c.from(&f))
	}
	return d
}

var (
	// errWithoutFacts is a record the analyst wrote before it kept what it
	// was shown: there is nothing exact to export, and a reconstruction is
	// not what it saw.
	errWithoutFacts = errors.New("recorded without what the analyst was shown")
	// errUnreadable is a record with a field outside its shape or set.
	errUnreadable = errors.New("a field outside its shape or closed set")
)

// sawFromDetail reads what sawDetail wrote, strictly: every number in the
// one form strconv writes it, every boolean as true or false, both words
// from their sets.
func sawFromDetail(d map[string]string) (forge.Facts, error) {
	if _, ok := d["saw_times_seen"]; !ok {
		return forge.Facts{}, errWithoutFacts
	}
	var f forge.Facts
	var ok bool
	if f.Kind, ok = forge.KindOf(d["saw_kind"]); !ok {
		return forge.Facts{}, errUnreadable
	}
	if f.Severity, ok = forge.SeverityOf(d["saw_severity"]); !ok {
		return forge.Facts{}, errUnreadable
	}
	for _, c := range sawInts {
		v := d[c.key]
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || strconv.Itoa(n) != v {
			return forge.Facts{}, errUnreadable
		}
		*c.into(&f) = n
	}
	for _, c := range sawBools {
		switch d[c.key] {
		case "true":
			*c.into(&f) = true
		case "false":
		default:
			return forge.Facts{}, errUnreadable
		}
	}
	return f, nil
}

// abstentionWords maps the words abstainWord records to internal/forge's.
// A record whose word is not here is not exported.
var abstentionWords = map[string]forge.Abstention{
	"not confident enough":                     forge.BelowThreshold,
	"did not hold without the attacker's text": forge.CounterfactualUnconfirmed,
	"no usable answer":                         forge.NoUsableAnswer,
}

// proposedVerdict is the verdict behind a state the analyst suggested; it
// suggests these three and no others.
func proposedVerdict(to string) (forge.Verdict, bool) {
	switch finding.State(to) {
	case finding.Triaged:
		return forge.Real, true
	case finding.FalsePositive:
		return forge.FalsePositive, true
	case finding.Benign:
		return forge.Benign, true
	}
	return forge.Verdict{}, false
}

// ruledVerdict is the verdict a person's ruling stands for, as the
// analyst's own counts read one: triaged, fixed and accepted all say it
// was real. Open and stale are no verdict.
func ruledVerdict(s finding.State) forge.Verdict {
	switch s {
	case finding.Triaged, finding.Accepted, finding.Fixed:
		return forge.Real
	case finding.FalsePositive:
		return forge.FalsePositive
	case finding.Benign:
		return forge.Benign
	}
	return forge.Verdict{}
}

// recordedConfidence reads the confidence as the analyst records it, two
// decimals.
func recordedConfidence(s string) (float64, bool) {
	c, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(c) || c < 0 || c > 1 ||
		strconv.FormatFloat(c, 'f', 2, 64) != s {
		return 0, false
	}
	return c, true
}

// ruling is a state a verified person moved a finding to, and where in the
// log they did.
type ruling struct {
	seq int64
	to  finding.State
}

// peoplesRulings is every ruling a verified person recorded, by finding,
// in the order the log holds them. A service account's is a program's
// rather than a judgement, and an unverified one is a name nobody proved;
// a model's is refused where it would be made and is not read here either.
func peoplesRulings(events []audit.Event) map[string][]ruling {
	known := map[finding.State]bool{}
	for _, s := range finding.States() {
		known[s] = true
	}
	out := map[string][]ruling{}
	for _, e := range events {
		to, ok := strings.CutPrefix(e.Action, "finding.")
		id := e.Detail["finding"]
		if !ok || id == "" || !known[finding.State(to)] {
			continue
		}
		if e.Kind != audit.KindHuman || !e.Verified {
			continue
		}
		out[id] = append(out[id], ruling{seq: e.Seq, to: finding.State(to)})
	}
	return out
}

// forgeSkips counts the analyst's records an export left out, by why.
type forgeSkips struct {
	WithoutFacts int `json:"without_facts"`
	Unreadable   int `json:"unreadable"`
}

// forgeEpisodes reads the analyst's records out of the log and pairs each
// with the rulings on its finding. Only the analyst's own records count:
// its agent name, written by runTriage, and a model's kind. An outside
// agent's proposal is a different record — its reason is prose a model
// wrote, and it was never part of the analyst's fixed plan.
func forgeEpisodes(events []audit.Event) ([]forge.Episode, forgeSkips) {
	rulings := peoplesRulings(events)
	var eps []forge.Episode
	var skips forgeSkips
	for _, e := range events {
		if (e.Action != finding.ProposalAction && e.Action != abstainAction) ||
			e.Detail["agent"] != "triage" || e.Kind != audit.KindAI {
			continue
		}
		ep, err := episodeOf(e, rulings[e.Detail["finding"]])
		switch {
		case errors.Is(err, errWithoutFacts):
			skips.WithoutFacts++
		case err != nil:
			skips.Unreadable++
		default:
			eps = append(eps, ep)
		}
	}
	return eps, skips
}

// episodeOf builds one episode from one analyst record. Every value is
// obtained from a constructor in internal/forge or parsed as a number;
// nothing is copied from the record as text.
func episodeOf(e audit.Event, rulings []ruling) (forge.Episode, error) {
	saw, err := sawFromDetail(e.Detail)
	if err != nil {
		return forge.Episode{}, err
	}
	ep := forge.Episode{Format: forge.Format, Seq: e.Seq, Saw: saw}
	var ok bool
	if ep.Entry, ok = forge.EntryOf(e.Hash); !ok {
		return forge.Episode{}, errUnreadable
	}
	if ep.Finding, ok = forge.FindingIDOf(e.Detail["finding"]); !ok {
		return forge.Episode{}, errUnreadable
	}
	if ep.Model, ok = forge.ModelOf(e.Model); !ok {
		return forge.Episode{}, errUnreadable
	}
	at, err := time.Parse(time.RFC3339Nano, e.At)
	if err != nil {
		return forge.Episode{}, errUnreadable
	}
	ep.At = at.UTC()
	if ep.Produced.Confidence, ok = recordedConfidence(e.Detail["confidence"]); !ok {
		return forge.Episode{}, errUnreadable
	}
	if e.Action == finding.ProposalAction {
		if ep.Produced.Verdict, ok = proposedVerdict(e.Detail["to"]); !ok {
			return forge.Episode{}, errUnreadable
		}
		ep.Produced.CounterfactualChanged = e.Detail["counterfactual"] == "changed"
	} else if ep.Produced.Abstained, ok = abstentionWords[e.Detail["why"]]; !ok {
		return forge.Episode{}, errUnreadable
	}
	// The last ruling after the analyst looked is the label: a person who
	// changed their mind is taken at their latest word, and one who put
	// the finding back to open has withdrawn their verdict.
	for _, r := range rulings {
		if r.seq > e.Seq {
			ep.Person, ep.DecidedSeq = ruledVerdict(r.to), r.seq
		}
	}
	if ep.Person.IsZero() {
		ep.DecidedSeq = 0
	}
	ep.Outcome = forge.OutcomeOf(ep.Produced, ep.Person)
	if err := ep.Validate(); err != nil {
		return forge.Episode{}, errUnreadable
	}
	return ep, nil
}

// ---- export ----------------------------------------------------------------

type forgeOptions struct {
	key, publicKey, out string
}

func forgeExport(root string, args []string) error {
	fs := flag.NewFlagSet("forge export", flag.ContinueOnError)
	var o forgeOptions
	fs.StringVar(&o.key, "key", "", "the dual signing key file (aertun content keygen makes one)")
	fs.StringVar(&o.publicKey, "public-key", "", "where to write the public key a reader verifies with")
	fs.StringVar(&o.out, "out", "", "where to write the episodes, as JSON lines (written 0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("forge export takes flags only: --key FILE --out FILE [--public-key FILE]")
	}
	sum, skips, err := runForgeExport(root, resolveCaller(root, flagToken), o, time.Now())
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"out": o.out, "summary": sum, "skipped": skips}) {
		return nil
	}
	w.Human("%s%d episode(s)%s written to %s\n", bold, sum.Episodes, reset, o.out)
	w.Human("  %d agreed, %d disagreed, %d abstained, %d undecided\n",
		sum.Agreed, sum.Disagreed, sum.Abstained, sum.Undecided)
	w.Human("  Merkle root %s, recorded in the audit log\n", sum.Root)
	if n := skips.WithoutFacts + skips.Unreadable; n > 0 {
		w.Human("  %s%d of the analyst's records left out: %d recorded before it "+
			"kept what it was shown, %d with a field this version cannot read%s\n",
			dim, n, skips.WithoutFacts, skips.Unreadable, reset)
	}
	w.Human("  %san episode holds counts and closed-set words only; the text the "+
		"analyst read beside them is never in it%s\n", dim, reset)
	return nil
}

// runForgeExport is the export, for a caller already resolved.
//
// Ordered so that nothing leaves unrecorded: the audit log's chain is
// checked before anything is read out of it, the export is recorded before
// the file is written, and a failure at any step writes no file.
func runForgeExport(root string, caller *Caller, o forgeOptions,
	now time.Time) (forge.Summary, forgeSkips, error) {

	if caller.Kind == audit.KindAI {
		return forge.Summary{}, forgeSkips{}, fmt.Errorf("an export is started by " +
			"a person. A model exporting what models were shown and how people " +
			"ruled is choosing what the next model learns, with nobody in the loop")
	}
	if o.key == "" || o.out == "" {
		return forge.Summary{}, forgeSkips{}, fmt.Errorf("forge export needs " +
			"--key FILE and --out FILE: episodes nobody can verify are a claim " +
			"about a claim")
	}
	k, err := loadSigningKey(o.key)
	if err != nil {
		return forge.Summary{}, forgeSkips{}, err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return forge.Summary{}, forgeSkips{}, err
	}
	// The rulings are the labels, and a label read from a log that fails
	// its own chain is one nobody can stand behind.
	if ok, problems := audit.Verify(events); !ok {
		return forge.Summary{}, forgeSkips{}, fmt.Errorf("the audit log does not "+
			"verify (entry %d: %s), so nothing is exported from it. Run aertun "+
			"auditlog verify", problems[0].Seq, problems[0].Reason)
	}
	eps, skips := forgeEpisodes(events)
	if len(eps) == 0 {
		return forge.Summary{}, skips, fmt.Errorf("there is nothing to export: "+
			"the analyst has no suggestion or abstention this version can read "+
			"(%d recorded before it kept what it was shown, %d unreadable). "+
			"Nothing was signed and no file was written",
			skips.WithoutFacts, skips.Unreadable)
	}
	body, sum, err := forge.Seal(eps, k, events[len(events)-1].Seq, now)
	if err != nil {
		return forge.Summary{}, skips, err
	}
	signer, err := forge.KeyID(k.PublicKey())
	if err != nil {
		return forge.Summary{}, skips, err
	}
	digest := sha256.Sum256(body)
	if err := recordE(root, caller.auditRecord(forgeExportedAction, "/forge",
		audit.Success, map[string]string{
			"merkle_root": sum.Root, "episodes": strconv.Itoa(sum.Episodes),
			"through_seq": strconv.FormatInt(sum.ThroughSeq, 10),
			"file_sha256": hex.EncodeToString(digest[:]), "signer": signer,
			"agreed": strconv.Itoa(sum.Agreed), "disagreed": strconv.Itoa(sum.Disagreed),
			"abstained": strconv.Itoa(sum.Abstained), "undecided": strconv.Itoa(sum.Undecided),
			"skipped_without_facts": strconv.Itoa(skips.WithoutFacts),
			"skipped_unreadable":    strconv.Itoa(skips.Unreadable),
		})); err != nil {
		return forge.Summary{}, skips, err
	}
	// 0o600: an episode names findings by id and says how people ruled on
	// them, which is this organisation's triage record.
	if err := atomicfile.Write(o.out, body, 0o600); err != nil {
		return forge.Summary{}, skips, fmt.Errorf("the export is recorded in the "+
			"audit log, and the file was not written: %w", err)
	}
	if o.publicKey != "" {
		if err := pack.WritePublicKey(o.publicKey, k.PublicKey()); err != nil {
			return forge.Summary{}, skips, err
		}
	}
	return sum, skips, nil
}

// ---- verify ----------------------------------------------------------------

func forgeVerify(root string, args []string) error {
	pos, rest := leadingArgs(args, 1)
	fs := flag.NewFlagSet("forge verify", flag.ContinueOnError)
	pubAt := fs.String("key", "", "the public key file the exporter published")
	inLog := fs.Bool("log", false, "also find the export's record in this store's audit log")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	files := append(pos, fs.Args()...)
	if len(files) != 1 {
		return fmt.Errorf("verify takes one FILE, the episodes")
	}
	if *pubAt == "" {
		return fmt.Errorf("verify needs --key FILE: a signature is checked " +
			"against a key the verifier was handed, never one the document supplies")
	}
	pub, err := pack.LoadPublicKey(*pubAt)
	if err != nil {
		return err
	}
	body, err := proof.ReadBounded(files[0], forge.MaxFile)
	if err != nil {
		return err
	}
	sum, _, err := forge.Verify(body, pub)
	if err != nil {
		return fmt.Errorf("%s: %w", files[0], err)
	}
	var recorded *audit.Event
	if *inLog {
		if recorded, err = forgeRecordFor(root, sum.Root); err != nil {
			return fmt.Errorf("%s: %w", files[0], err)
		}
	}
	signer, err := forge.KeyID(pub)
	if err != nil {
		return err
	}
	out := map[string]any{"summary": sum, "signer": signer}
	if recorded != nil {
		out["recorded_seq"] = recorded.Seq
	}
	if w.JSON(out) {
		return nil
	}
	w.Human("both signatures hold, by key %s.\n", signer)
	w.Human("%s%d episode(s)%s through audit entry %d, sealed %s\n", bold,
		sum.Episodes, reset, sum.ThroughSeq, sum.ExportedAt.Format(time.RFC3339))
	w.Human("  %d agreed, %d disagreed, %d abstained, %d undecided\n",
		sum.Agreed, sum.Disagreed, sum.Abstained, sum.Undecided)
	if recorded != nil {
		w.Human("  recorded in this store's audit log at entry %d, %s\n",
			recorded.Seq, recorded.At)
	}
	return nil
}

// forgeRecordFor finds the record of the export whose episodes have this
// Merkle root, in a log whose chain holds: a record in a log that has been
// rewritten says only what whoever rewrote it wanted.
func forgeRecordFor(root, merkleRoot string) (*audit.Event, error) {
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, err
	}
	if ok, problems := audit.Verify(events); !ok {
		return nil, fmt.Errorf("this store's audit log does not verify (entry %d: "+
			"%s), so it cannot vouch for an export", problems[0].Seq, problems[0].Reason)
	}
	for i := range events {
		e := events[i]
		if e.Action == forgeExportedAction && e.Outcome == audit.Success &&
			e.Detail["merkle_root"] == merkleRoot {
			return &events[i], nil
		}
	}
	return nil, fmt.Errorf("this store's audit log records no export of these " +
		"episodes: the file verifies against the key, and this store did not " +
		"write it")
}
