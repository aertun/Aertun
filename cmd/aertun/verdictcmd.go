// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/verdict"
)

// Another vendor's AI verdicts, scored against what people here decided.
//
// `verdict import` takes a product's export of what its AI said, alert by
// alert, in a strict shape that carries no text; `verdict list` says what is
// held; `verdict prove` joins them to the decisions people made on the
// findings those alerts raised here, over a declared period, and signs a
// verdicts proof (internal/proof) that `proof verify` checks offline. The
// product does not have to cooperate, and nothing it wrote reaches the proof.

// MaxStoredVerdicts bounds what the store holds across every product. The
// store is one document rewritten whole on each import; a bound is what
// keeps that a decision rather than a growth nobody chose.
const MaxStoredVerdicts = 250_000

// maxVerdictStore bounds the stored document when it is read back.
const maxVerdictStore = 128 << 20

func verdictsPath(root string) string { return filepath.Join(root, "verdicts.json") }

// verdictStore is the stored document.
type verdictStore struct {
	Verdicts []verdict.Verdict `json:"verdicts"`
}

func cmdVerdict(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("verdict needs import, list or prove")
	}
	switch args[0] {
	case "import":
		return verdictImport(root, args[1:])
	case "list":
		return verdictList(root, args[1:])
	case "prove":
		return verdictProve(root, args[1:])
	default:
		return fmt.Errorf("unknown verdict command %q; try import, list or prove", args[0])
	}
}

func verdictImport(root string, args []string) error {
	fs := flag.NewFlagSet("verdict import", flag.ContinueOnError)
	source := fs.String("source", "", "the product, by a short name you choose (2 to 32 of a-z, 0-9 and -)")
	format := fs.String("format", "", "jsonl or csv (default: from the file's extension)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *source == "" {
		return fmt.Errorf("verdict import takes one FILE and --source NAME")
	}
	at := fs.Arg(0)
	f := verdict.Format(*format)
	if f == "" {
		switch strings.ToLower(filepath.Ext(at)) {
		case ".csv":
			f = verdict.CSV
		case ".jsonl", ".ndjson":
			f = verdict.JSONLines
		default:
			return fmt.Errorf("say --format jsonl or --format csv: the file's name does not")
		}
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActTriage, auth.AreaSecurity); err != nil {
		return err
	}
	body, err := proof.ReadBounded(at, verdict.MaxImport)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	in, err := verdict.Parse(bytes.NewReader(body), f, *source, now)
	if err != nil {
		return fmt.Errorf("%s: %w; nothing was imported", filepath.Base(at), err)
	}
	added, repeated := 0, 0
	err = atomicfile.Update(verdictsPath(root), func(s *verdictStore) error {
		held := map[string][]verdict.Verdict{}
		for _, v := range s.Verdicts {
			held[v.Source+"\x00"+v.Alert] = append(held[v.Source+"\x00"+v.Alert], v)
		}
	next:
		for _, v := range in {
			k := v.Source + "\x00" + v.Alert
			for _, h := range held[k] {
				if verdict.Same(h, v) {
					repeated++
					continue next
				}
			}
			held[k] = append(held[k], v)
			s.Verdicts = append(s.Verdicts, v)
			added++
		}
		if len(s.Verdicts) > MaxStoredVerdicts {
			return fmt.Errorf("the store would hold %d verdicts and holds at most %d; "+
				"nothing was imported", len(s.Verdicts), MaxStoredVerdicts)
		}
		if added == 0 {
			return atomicfile.ErrUnchanged
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := recordE(root, audit.Record{Action: "verdict.imported", Resource: "/verdicts",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind, Model: caller.Model,
		Verified: caller.Verified, Detail: map[string]string{"source": *source,
			"added": fmt.Sprint(added), "repeated": fmt.Sprint(repeated),
			"sha256": proof.SHA256(body)["sha256"]}}); err != nil {
		return err
	}
	if w.JSON(map[string]any{"source": *source, "added": added, "repeated": repeated}) {
		return nil
	}
	w.Human("%d verdict(s) from %s imported", added, *source)
	if repeated > 0 {
		w.Human("; %d already held", repeated)
	}
	w.Human("\n")
	return nil
}

// loadVerdicts reads the store strictly: it is this program's own file,
// and a document that does not read as one is refused rather than scored.
func loadVerdicts(root string, now time.Time) ([]verdict.Verdict, error) {
	body, err := proof.ReadBounded(verdictsPath(root), maxVerdictStore)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s verdictStore
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s does not read as the verdict store: %w", verdictsPath(root), err)
	}
	for i, v := range s.Verdicts {
		// Validated against the moment it was taken in, which is the only
		// clock the stored times were checked against.
		if err := v.Validate(v.Imported); err != nil || v.Imported.After(now.Add(verdict.Skew)) {
			return nil, fmt.Errorf("stored verdict %d is not one this program would have imported", i+1)
		}
	}
	return s.Verdicts, nil
}

func verdictList(root string, args []string) error {
	fs := flag.NewFlagSet("verdict list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActView, auth.AreaSecurity); err != nil {
		return err
	}
	vs, err := loadVerdicts(root, time.Now().UTC())
	if err != nil {
		return err
	}
	type row struct {
		Source   string    `json:"source"`
		Verdicts int       `json:"verdicts"`
		Alerts   int       `json:"alerts"`
		First    time.Time `json:"first"`
		Last     time.Time `json:"last"`
	}
	by := map[string]*row{}
	alerts := map[string]map[string]bool{}
	for _, v := range vs {
		r := by[v.Source]
		if r == nil {
			r = &row{Source: v.Source, First: v.At, Last: v.At}
			by[v.Source], alerts[v.Source] = r, map[string]bool{}
		}
		r.Verdicts++
		alerts[v.Source][v.Alert] = true
		if v.At.Before(r.First) {
			r.First = v.At
		}
		if v.At.After(r.Last) {
			r.Last = v.At
		}
	}
	rows := make([]row, 0, len(by))
	for s, r := range by {
		r.Alerts = len(alerts[s])
		rows = append(rows, *r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Source < rows[j].Source })
	if w.JSON(map[string]any{"sources": rows}) {
		return nil
	}
	if len(rows) == 0 {
		w.Human("no verdicts held; aertun verdict import FILE --source NAME brings a product's in\n")
		return nil
	}
	for _, r := range rows {
		w.Human("%s%s%s  %d verdict(s) on %d alert(s), %s to %s\n", bold, r.Source, reset,
			r.Verdicts, r.Alerts, r.First.Format("2006-01-02"), r.Last.Format("2006-01-02"))
	}
	return nil
}

// parseDay reads a period's edge: a date, which is its midnight UTC, or an
// RFC 3339 time.
func parseDay(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not a date (2006-01-02) or an RFC 3339 time", s)
	}
	return t.UTC(), nil
}

func verdictProve(root string, args []string) error {
	fs := flag.NewFlagSet("verdict prove", flag.ContinueOnError)
	source := fs.String("source", "", "the product whose verdicts are scored")
	sinceAt := fs.String("since", "", "the period's start: a date or an RFC 3339 time")
	untilAt := fs.String("until", "", "the period's end, not included (default: now)")
	tolerance := fs.Float64("tolerance", 0, "the false-closure rate the product is held to, "+
		"between 0 and 1, declared before the proof is made (required)")
	labels := fs.String("labels", "people", "where dispositions come from: people "+
		"(verified people's decisions here) or reported (the product's own export says)")
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" || *sinceAt == "" || *keyAt == "" {
		return fmt.Errorf("verdict prove needs --source NAME, --since DATE and --key FILE: " +
			"an unsigned score is a claim about a claim")
	}
	if !(*tolerance > 0 && *tolerance < 1) {
		return fmt.Errorf("--tolerance is the false-closure rate the product is held to, " +
			"between 0 and 1 and more than none, and it has no default: it is the claim, " +
			"so it is chosen before the numbers are seen")
	}
	var ls verdict.LabelSource
	switch *labels {
	case "people":
		ls = verdict.People
	case "reported":
		ls = verdict.Reported
	default:
		return fmt.Errorf("--labels is people or reported")
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
	// Tune, like calibrating the analyst: a signed measurement of a product
	// in this organisation's name is one somebody may take into a contract.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	vs, err := loadVerdicts(root, now)
	if err != nil {
		return err
	}
	in := verdict.Input{Source: *source, Since: since, Until: until, Labels: ls, Verdicts: vs}
	var materials []proof.Material
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	if ok, problems := audit.Verify(events); !ok {
		p := problems[0]
		return fmt.Errorf("the audit log does not verify, so no decision can be taken "+
			"from it: entry %d: %s", p.Seq, p.Reason)
	}
	if len(events) > 0 {
		head := events[len(events)-1]
		materials = append(materials, proof.Material{Name: "audit-log",
			Digest: proof.Digest{"sha256": head.Hash}, Entries: len(events)})
	}
	if ls == verdict.People {
		reg, _, err := finding.Load(findingsPath(root))
		if err != nil {
			return err
		}
		kept, _ := peoplesVerdicts(events)
		in.Findings = reg.All(until)
		in.Decisions = decisionsFrom(events)
		in.People = decisionsFrom(kept)
		register, err := os.ReadFile(findingsPath(root))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		materials = append(materials, proof.Material{Name: "finding-register",
			Digest: proof.SHA256(register), Entries: len(in.Findings)})
	}
	score := verdict.Compute(in)
	var lines bytes.Buffer
	for _, v := range score.Considered {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		lines.Write(b)
		lines.WriteByte('\n')
	}
	excluded := map[string]int{}
	for r, n := range score.Excluded {
		excluded[string(r)] = n
	}
	st, err := proof.ProveVerdicts(proof.VerdictsInput{Source: *source, Labels: string(ls),
		Since: since, Until: until, Tolerance: *tolerance, Lines: lines.Bytes(),
		Considered: len(score.Considered), Counted: score.Counted, Alerts: score.Alerts,
		Excluded: excluded, FalseClosures: score.FalseClosures, FalseClosed: score.FalseClosed,
		ReviewCoverage: score.ReviewCoverage, DeliveredFirst: score.DeliveredFirst,
		Agreement: score.Agreement, EscalationsClosed: score.EscalationsClosed,
		Abstentions: score.Abstentions, Consistency: score.Consistency,
		Materials: materials, Program: version, Now: now})
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
		// Kept in the store as well, so the proving ground shows it.
		keepMade(root, env, pubDoc, caller.Name)
	}
	ev := st.Predicate.Verdicts
	if err := recordE(root, audit.Record{Action: "verdict.proved", Resource: "/verdicts",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind, Model: caller.Model,
		Verified: caller.Verified, Detail: map[string]string{"source": *source,
			"verdict": string(st.Predicate.Verdict), "tolerance": fmt.Sprint(*tolerance),
			"closures": fmt.Sprint(ev.FalseClosures.N), "false_closures": fmt.Sprint(ev.FalseClosures.K),
			"since": ev.Since, "until": ev.Until}}); err != nil {
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
