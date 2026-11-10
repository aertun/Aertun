// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/adjudicate"
	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/ops"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proving"
	"github.com/aertun/aertun/internal/verdict"
)

// Blind adjudication: closures judged again, by a person, on a random sample
// committed before anybody looked (internal/adjudicate), and signed as an
// adjudication proof (internal/proof).
//
// `adjudicate draw` reads every closure a product's AI made in a period and
// every closure people made, draws a sample from each at random, writes it
// to the store and commits it to the audit log before the first item can be
// shown. Each item is then shown to a reviewer with its evidence and nothing
// that says who closed it, how, or which of the two it came from — the
// console's Adjudication screen, or `adjudicate next` and `judge`. Nobody who
// closed an item may judge it, an item is judged once, and a judgement is a
// record in the log, never a decision on the finding, so a product that
// learns from analysts cannot learn the answers. `adjudicate prove` signs the
// result once every item is judged.

func samplesDir(root string) string { return filepath.Join(root, "adjudication") }

func samplePath(root, id string) string { return filepath.Join(samplesDir(root), id+".json") }

// maxSampleFile bounds a sample file: the population is two lists of
// finding ids, a few hundred thousand at most.
const maxSampleFile = 64 << 20

// loadSample reads a sample strictly, with its bytes, and checks its
// selection is what its seed and population decide.
func loadSample(root, id string) (*adjudicate.Sample, []byte, error) {
	if !adjudicate.ValidID(id) {
		return nil, nil, &ops.Refusal{Reason: "a sample's id is 16 hexadecimal characters"}
	}
	body, err := proof.ReadBounded(samplePath(root, id), maxSampleFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, &ops.Refusal{Reason: "no sample has that id"}
	}
	if err != nil {
		return nil, nil, err
	}
	var s adjudicate.Sample
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, nil, fmt.Errorf("sample %s does not read as one: %w", id, err)
	}
	if err := s.Check(); err != nil {
		return nil, nil, err
	}
	return &s, body, nil
}

func sampleIDs(root string) ([]string, error) {
	des, err := os.ReadDir(samplesDir(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range des {
		if id, ok := strings.CutSuffix(d.Name(), ".json"); ok && adjudicate.ValidID(id) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// provingRegistry is every proving-ground operation for the store at root:
// the kept proofs (internal/proving) and the blind review.
func provingRegistry(root string) *ops.Registry {
	r := proving.Ops(root)
	addAdjudicationOps(r, root)
	return r
}

func addAdjudicationOps(r *ops.Registry, root string) {
	r.Add(ops.Op{Name: "list_samples", CLI: "adjudicate list",
		Summary: "the blind samples drawn for review, and how far each review has got",
		Needs:   auth.ActView, Area: auth.AreaSecurity, Effect: ops.Read, PeopleOnly: true,
		Run: func(c ops.Call) (*answer, error) {
			ids, err := sampleIDs(root)
			if err != nil {
				return nil, err
			}
			events, err := audit.Read(auditPath(root))
			if err != nil {
				return nil, err
			}
			rows := ops.List()
			for _, id := range ids {
				s, _, err := loadSample(root, id)
				if err != nil {
					rows.Add(object().With("id", ours(id)).With("broken", ours(err.Error())))
					continue
				}
				done := adjudicate.Progress(events, id)
				ai, human := s.Counts()
				rows.Add(object().With("id", ours(s.ID)).With("source", ours(s.Source)).
					With("since", ours(s.Since)).With("until", ours(s.Until)).
					With("items", ours(len(s.Items))).With("judged", ours(len(done))).
					With("ai_items", ours(ai)).With("human_items", ours(human)))
			}
			return object().With("samples", rows), nil
		}})
	r.Add(ops.Op{Name: "next_review_item", CLI: "adjudicate next",
		Summary: "the next item of a sample for you to judge, with its evidence and nothing that " +
			"says who closed it or how",
		Needs: auth.ActTriage, Area: auth.AreaSecurity, Effect: ops.Read, PeopleOnly: true,
		Args: []ops.Arg{{Name: "sample", Kind: ops.Text, Required: true, Positional: true,
			About: "the sample's id"}},
		Run: func(c ops.Call) (*answer, error) { return nextItem(root, c) }})
	r.Add(ops.Op{Name: "judge_item", CLI: "adjudicate judge",
		Summary: "judge one sampled item real, false-positive or benign, with your reason",
		Needs:   auth.ActTriage, Area: auth.AreaSecurity, Effect: ops.Change, PeopleOnly: true,
		Audit: "adjudication.judging",
		Args: []ops.Arg{
			{Name: "sample", Kind: ops.Text, Required: true, Positional: true, About: "the sample's id"},
			{Name: "item", Kind: ops.Number, Required: true, About: "the item's number"},
			{Name: "judgement", Kind: ops.Text, Required: true, About: "real, false-positive or benign"},
			{Name: "because", Kind: ops.Text, Required: true, Max: adjudicate.MaxBecause,
				About: "why, on one line: whoever checks the review reads it"},
		},
		Run: func(c ops.Call) (*answer, error) { return judgeItem(root, c) }})
}

// mayJudge reports whether the caller may judge a finding: not when they
// closed it, as the log records them under its pseudonym.
func mayJudge(root, caller, findingID string, decisions []finding.Decision) (bool, error) {
	l, err := openAudit(root)
	if err != nil {
		return false, err
	}
	for by := range adjudicate.Closers(findingID, decisions) {
		if by == caller || l.Matches(by, caller) {
			return false, nil
		}
	}
	return true, nil
}

func nextItem(root string, c ops.Call) (*answer, error) {
	s, _, err := loadSample(root, c.Args.Text("sample"))
	if err != nil {
		return nil, err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, err
	}
	decisions := decisionsFrom(events)
	pending := s.Pending(adjudicate.Progress(events, s.ID))
	reg, _, err := finding.Load(findingsPath(root))
	if err != nil {
		return nil, err
	}
	byID := map[string]finding.Finding{}
	for _, f := range reg.All(c.Now) {
		byID[f.ID] = f
	}
	out := object().With("sample", ours(s.ID)).With("items", ours(len(s.Items))).
		With("remaining", ours(len(pending)))
	skipped := 0
	for _, it := range pending {
		ok, err := mayJudge(root, c.Caller.Name(), it.Finding, decisions)
		if err != nil {
			return nil, err
		}
		if !ok {
			skipped++
			continue
		}
		f, found := byID[it.Finding]
		if !found {
			return nil, fmt.Errorf("item %d names a finding the register no longer holds", it.N)
		}
		// What the reviewer sees: the finding as it was raised and its
		// evidence. Never its state, its decisions, who closed it, the
		// product's verdict, or which stratum chose it.
		return out.With("skipped_as_yours", ours(skipped)).With("item", object().
			With("n", ours(it.N)).With("finding", ours(f.ID)).
			With("title", outside(f.Title)).With("entity", outside(f.Entity.String())).
			With("rule", ours(f.Source)).With("severity", ours(int(f.Severity))).
			With("first", ours(f.First)).With("seen", ours(f.Seen)).
			With("evidence", listOf(f.Evidence, func(e finding.Evidence) *answer {
				return object().With("at", ours(e.At)).With("from", ours(e.Source)).
					With("what", outside(e.What))
			}))), nil
	}
	return out.With("skipped_as_yours", ours(skipped)), nil
}

func judgeItem(root string, c ops.Call) (*answer, error) {
	s, _, err := loadSample(root, c.Args.Text("sample"))
	if err != nil {
		return nil, err
	}
	n := c.Args.Number("item", 0)
	it, ok := s.Item(n)
	if !ok {
		return nil, &ops.Refusal{Reason: fmt.Sprintf("sample %s has no item %d", s.ID, n)}
	}
	j := adjudicate.Judgement{Sample: s.ID, N: n, Finding: it.Finding,
		Says: verdict.Word(c.Args.Text("judgement")), Because: c.Args.Text("because")}
	if err := j.Validate(); err != nil {
		return nil, &ops.Refusal{Reason: err.Error()}
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, err
	}
	if adjudicate.Progress(events, s.ID)[n] {
		return nil, &ops.Refusal{Reason: fmt.Sprintf("item %d is already judged, and a review "+
			"counts each item once: a second judgement would let an answer nobody liked be replaced",
			n)}
	}
	ok, err = mayJudge(root, c.Caller.Name(), it.Finding, decisionsFrom(events))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &ops.Refusal{Reason: fmt.Sprintf("you closed the finding item %d is, so "+
			"you cannot judge it again blind", n)}
	}
	if err := c.Caller.Record(adjudicate.JudgedAction, j.Detail()); err != nil {
		return nil, err
	}
	return object().With("sample", ours(s.ID)).With("item", ours(n)).
		With("judged", ours(string(j.Says))), nil
}

func cmdAdjudicate(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("adjudicate needs draw, list, next, judge, size or prove")
	}
	reg := provingRegistry(root)
	switch args[0] {
	case "draw":
		return adjudicateDraw(root, args[1:])
	case "list":
		return runOpCommand(root, reg, "list_samples", args[1:], humanSamples)
	case "next":
		return runOpCommand(root, reg, "next_review_item", args[1:], humanNextItem)
	case "judge":
		return runOpCommand(root, reg, "judge_item", args[1:], func(a *answer) string {
			return fmt.Sprintf("item %s judged %s", a.Get("item").Text(), a.Get("judged").Text())
		})
	case "size":
		return adjudicateSize(args[1:])
	case "prove":
		return adjudicateProve(root, args[1:])
	default:
		return fmt.Errorf("unknown adjudicate command %q; try draw, list, next, judge, size or prove", args[0])
	}
}

func adjudicateDraw(root string, args []string) error {
	fs := flag.NewFlagSet("adjudicate draw", flag.ContinueOnError)
	source := fs.String("source", "", "the product whose AI's closures are sampled")
	sinceAt := fs.String("since", "", "the period's start: a date or an RFC 3339 time")
	untilAt := fs.String("until", "", "the period's end, not included (default: now)")
	per := fs.Int("per", 0, "how many closures to sample from each stratum; aertun adjudicate "+
		"size says how many a target needs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" || *sinceAt == "" || *per <= 0 {
		return fmt.Errorf("adjudicate draw needs --source NAME, --since DATE and --per N")
	}
	now := time.Now().UTC()
	since, err := parseDay(*sinceAt)
	if err != nil {
		return err
	}
	until := now
	if *untilAt != "" {
		if until, err = parseDay(*untilAt); err != nil {
			return err
		}
	}
	if !since.Before(until) || until.After(now) {
		return fmt.Errorf("the period starts before it ends, and does not end in the future")
	}
	caller := resolveCaller(root, flagToken)
	// Tune: a sample decides what a product will be measured on.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("a sample is drawn by a person: a model choosing what it will be measured on " +
			"is the thing under test choosing its test")
	}
	vs, err := loadVerdicts(root, now)
	if err != nil {
		return err
	}
	reg, _, err := finding.Load(findingsPath(root))
	if err != nil {
		return err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	if ok, problems := audit.Verify(events); !ok {
		p := problems[0]
		return fmt.Errorf("the audit log does not verify, so nothing can be committed to it: "+
			"entry %d: %s", p.Seq, p.Reason)
	}
	kept, _ := peoplesVerdicts(events)
	pop := adjudicate.Closures(adjudicate.PopulationInput{Source: *source, Since: since, Until: until,
		Verdicts: vs, Findings: reg.All(until), People: decisionsFrom(kept)})
	seed, err := adjudicate.NewSeed(rand.Reader)
	if err != nil {
		return err
	}
	s, err := adjudicate.Draw(*source, since, until, "", pop, seed, *per)
	if err != nil {
		return err
	}
	doc, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(samplesDir(root), 0o700); err != nil {
		return err
	}
	// The file first and the commitment second: a commitment to a file that
	// was never written could never be checked, and a file nobody committed
	// is one no proof will accept.
	if err := atomicfile.Write(samplePath(root, s.ID), append(doc, '\n'), 0o600); err != nil {
		return err
	}
	if err := recordE(root, caller.auditRecord(adjudicate.DrawnAction, "/adjudication/"+s.ID,
		audit.Success, s.CommitDetail())); err != nil {
		return err
	}
	ai, human := s.Counts()
	if w.JSON(map[string]any{"sample": s.ID, "items": len(s.Items), "ai": ai, "human": human,
		"population_ai": len(pop.AI), "population_human": len(pop.Human), "unlinked": pop.Unlinked}) {
		return nil
	}
	w.Human("sample %s: %d item(s), %d from %d closure(s) by %s's AI and %d from %d by people; "+
		"committed to the audit log. Review it on the console's Adjudication screen or with "+
		"aertun adjudicate next %s\n", s.ID, len(s.Items), ai, len(pop.AI), *source, human,
		len(pop.Human), s.ID)
	return nil
}

func adjudicateSize(args []string) error {
	fs := flag.NewFlagSet("adjudicate size", flag.ContinueOnError)
	rate := fs.Float64("rate", 0.01, "the false-closure rate to show a product is under")
	confidence := fs.Float64("confidence", 0.95, "how sure the bound must be")
	failures := fs.Int("failures", 0, "how many sampled closures you expect to be judged real")
	if err := fs.Parse(args); err != nil {
		return err
	}
	n, err := adjudicate.Size(*rate, *confidence, *failures)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"per_stratum": n, "rate": *rate, "confidence": *confidence,
		"failures": *failures}) {
		return nil
	}
	w.Human("%d reviewed closure(s) per stratum: with %d of them judged real, the exact one-sided "+
		"bound at %v is at or under %v\n", n, *failures, *confidence, *rate)
	return nil
}

func adjudicateProve(root string, args []string) error {
	fs := flag.NewFlagSet("adjudicate prove", flag.ContinueOnError)
	tolerance := fs.Float64("tolerance", 0, "the false-closure rate the product's AI is held to (required)")
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	var id string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if id == "" || *keyAt == "" {
		return fmt.Errorf("adjudicate prove takes SAMPLE --tolerance R --key FILE")
	}
	if !(*tolerance > 0 && *tolerance < 1) {
		return fmt.Errorf("--tolerance is the false-closure rate the product's AI is held to, " +
			"between 0 and 1, and has no default: it is the claim")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	s, body, err := loadSample(root, id)
	if err != nil {
		return err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	if ok, problems := audit.Verify(events); !ok {
		p := problems[0]
		return fmt.Errorf("the audit log does not verify: entry %d: %s", p.Seq, p.Reason)
	}
	r, err := adjudicate.Verify(s, events)
	if err != nil {
		return err
	}
	head := events[len(events)-1]
	st, err := proof.ProveAdjudication(proof.AdjudicationInput{Source: s.Source, Since: s.Since,
		Until: s.Until, Tolerance: *tolerance, SampleFile: body, Sample: s.ID,
		Committed: proof.AuditEntry{Seq: r.Commit.Seq, Hash: r.Commit.Hash,
			At: r.Commit.At.UTC().Format(time.RFC3339Nano)},
		EarlierDraws: r.EarlierDraws, PopulationAI: len(s.Population.AI),
		PopulationHuman: len(s.Population.Human), Unlinked: s.Population.Unlinked,
		Reviewers: r.Reviewers, AI: r.AI, Human: r.Human, RealAI: r.RealAI, RealHuman: r.RealHuman,
		Materials: []proof.Material{{Name: "audit-log", Digest: proof.Digest{"sha256": head.Hash},
			Entries: len(events)}},
		Program: version, Now: time.Now().UTC()})
	if err != nil {
		return err
	}
	env, err := proof.Seal(st, k)
	if err != nil {
		return err
	}
	doc, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	doc = append(doc, '\n')
	if *pubAt != "" {
		if err := pack.WritePublicKey(*pubAt, k.PublicKey()); err != nil {
			return err
		}
	}
	if pubDoc, err := json.Marshal(k.PublicKey()); err == nil {
		keepMade(root, env, pubDoc, caller.Name)
	}
	if err := recordE(root, caller.auditRecord("adjudication.proved", "/adjudication/"+s.ID,
		audit.Success, map[string]string{"sample": s.ID, "verdict": string(st.Predicate.Verdict),
			"ai":    strconv.Itoa(r.AI.K) + "/" + strconv.Itoa(r.AI.N),
			"human": strconv.Itoa(r.Human.K) + "/" + strconv.Itoa(r.Human.N)})); err != nil {
		return err
	}
	if *outAt == "" {
		if _, err := os.Stdout.Write(doc); err != nil {
			return err
		}
	} else {
		if err := atomicfile.Write(*outAt, doc, 0o600); err != nil {
			return err
		}
		if !w.JSON(summary(st)) {
			w.Human("%s\n", describe(st))
		}
	}
	return notProven(st)
}

func humanSamples(a *answer) string {
	var b strings.Builder
	rows := a.Get("samples").Items()
	if len(rows) == 0 {
		return "no samples drawn; aertun adjudicate draw --source NAME --since DATE --per N draws one"
	}
	for _, r := range rows {
		if br := r.Get("broken"); br != nil {
			fmt.Fprintf(&b, "%s  cannot be read: %s\n", r.Get("id").Text(), br.Text())
			continue
		}
		fmt.Fprintf(&b, "%s%s%s  %s, %s judged of %s (%s from the AI, %s from people)\n", bold,
			r.Get("id").Text(), reset, r.Get("source").Text(), r.Get("judged").Text(),
			r.Get("items").Text(), r.Get("ai_items").Text(), r.Get("human_items").Text())
	}
	return strings.TrimRight(b.String(), "\n")
}

func humanNextItem(a *answer) string {
	it := a.Get("item")
	if it == nil {
		return fmt.Sprintf("nothing left in sample %s for you to judge (%s remaining, %s of them yours)",
			a.Get("sample").Text(), a.Get("remaining").Text(), a.Get("skipped_as_yours").Text())
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%sitem %s of %s%s  (%s remaining)\n  %s  [%s, severity %s]\n  entity (from the log, untrusted): %s\n",
		bold, it.Get("n").Text(), a.Get("items").Text(), reset, a.Get("remaining").Text(),
		it.Get("title").Text(), it.Get("rule").Text(), it.Get("severity").Text(), it.Get("entity").Text())
	for _, e := range it.Get("evidence").Items() {
		fmt.Fprintf(&b, "  %s  %s (untrusted): %s\n", e.Get("at").Text(), e.Get("from").Text(), e.Get("what").Text())
	}
	fmt.Fprintf(&b, "judge it with: aertun adjudicate judge %s --item %s --judgement real|false-positive|benign --because \"…\"",
		a.Get("sample").Text(), it.Get("n").Text())
	return b.String()
}
