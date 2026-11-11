// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package proving declares the proving ground's operations: what has been
// proven, refuted and left inconclusive in a store, read and added to the same
// way on the command line, in the console and by agents (internal/ops).
package proving

import (
	"errors"
	"strings"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/ops"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
)

// Kept proofs: what has been proven, refuted and left inconclusive here,
// whose key signed each, and whether each still verifies. A proof's words
// are labelled by where they came from. A calibration certificate's and a
// verdicts proof's claim and checks are rebuilt from their numbers and
// closed sets whenever they are opened (internal/proof), so they are this
// program's. A detection proof names the rule it checked — a file name and a
// title chosen by whoever submitted the rule, which may be the model under
// test — so its subject, claim, check details and materials are labelled as
// written outside, as anything that could be either is.

// proofKinds names each predicate by the word every face shows.
var proofKinds = map[string]string{
	proof.PredicateDetection:      "detection",
	proof.PredicateCalibration:    "calibration",
	proof.PredicateVerdicts:       "verdicts",
	proof.PredicateReconciliation: "reconciliation",
	proof.PredicateAdjudication:   "adjudication",
	proof.PredicateClaim:          "claim",
	proof.PredicateNotAffected:    "not-affected",
}

// kindWords are the kinds a listing can be narrowed to.
var kindWords = []string{"detection", "calibration", "verdicts", "reconciliation", "adjudication", "claim", "not-affected"}

func proofKind(st *proof.Statement) string {
	if k, ok := proofKinds[st.PredicateType]; ok {
		return k
	}
	return "unknown"
}

// wordsFrom is how a proof's words are labelled: its own for the kinds whose
// words are rebuilt from numbers, outside for the rest.
func wordsFrom(st *proof.Statement) func(string) *ops.Answer {
	if st.Predicate.Calibration != nil || st.Predicate.Verdicts != nil ||
		st.Predicate.Reconciliation != nil || st.Predicate.Adjudication != nil ||
		st.Predicate.ClaimTest != nil || st.Predicate.NotAffected != nil {
		return ops.OursText
	}
	return ops.Outside
}

func entryRow(e proofstore.Entry) *ops.Answer {
	row := ops.Object().With("id", ops.Ours(e.ID)).With("kept_at", ops.Ours(e.KeptAt)).
		With("kept_by", ops.Ours(e.KeptBy)).With("origin", ops.Ours(e.Origin)).With("key_id", ops.Ours(e.KeyID))
	if e.Broken != "" {
		return row.With("broken", ops.Ours(e.Broken))
	}
	st := e.Statement
	words := wordsFrom(st)
	row.With("kind", ops.Ours(proofKind(st))).With("verdict", ops.Ours(string(st.Predicate.Verdict))).
		With("subject", words(st.Subject[0].Name)).With("claim", words(st.Predicate.Claim)).
		With("verified_at", ops.Ours(st.Predicate.VerifiedAt))
	if c := st.Predicate.Calibration; c != nil {
		row.With("expires", ops.Ours(c.Expires))
	}
	return row
}

// Source is where the operations read kept proofs from: the store, or a
// recorded case (the context twin), so a replay is answered by the same
// operations over what was kept when it was recorded.
type Source interface {
	List() ([]proofstore.Entry, error)
	Get(id string) (proofstore.Entry, error)
}

// Store is the kept proofs of the store at its root, read and checked again
// on every call.
type Store string

// List is every kept proof.
func (s Store) List() ([]proofstore.Entry, error) { return proofstore.List(string(s)) }

// Get is one kept proof.
func (s Store) Get(id string) (proofstore.Entry, error) { return proofstore.Get(string(s), id) }

// Recorded is kept proofs as they were read once: what a recorded case holds.
type Recorded []proofstore.Entry

// List is every recorded proof.
func (r Recorded) List() ([]proofstore.Entry, error) {
	return append([]proofstore.Entry(nil), r...), nil
}

// Get is one recorded proof.
func (r Recorded) Get(id string) (proofstore.Entry, error) {
	for _, e := range r {
		if e.ID == id {
			return e, nil
		}
	}
	return proofstore.Entry{}, errors.New("no proof is kept with that id")
}

func listProofs(src Source) func(ops.Call) (*ops.Answer, error) {
	return func(c ops.Call) (*ops.Answer, error) {
		kind := c.Args.Text("kind")
		if kind != "" && !containsWord(kindWords, kind) {
			return nil, &ops.Refusal{Reason: "kind is one of " + strings.Join(kindWords, ", ")}
		}
		limit := c.Args.Number("limit", 50)
		if limit < 1 || limit > 500 {
			return nil, &ops.Refusal{Reason: "limit is between 1 and 500"}
		}
		all, err := src.List()
		if err != nil {
			return nil, err
		}
		rows := ops.List()
		shown, broken := 0, 0
		counts := map[string]int{}
		for _, e := range all {
			if e.Broken != "" {
				broken++
			} else {
				counts[proofKind(e.Statement)+" "+string(e.Statement.Predicate.Verdict)]++
			}
			if kind != "" && (e.Statement == nil || proofKind(e.Statement) != kind) {
				continue
			}
			if shown < limit {
				rows.Add(entryRow(e))
				shown++
			}
		}
		return ops.Object().With("proofs", rows).With("kept", ops.Ours(len(all))).
			With("broken", ops.Ours(broken)).With("by_kind_and_verdict", ops.ByKey(counts, func(n int) *ops.Answer {
			return ops.Ours(n)
		})), nil
	}
}

func containsWord(set []string, w string) bool {
	for _, s := range set {
		if s == w {
			return true
		}
	}
	return false
}

func readProof(src Source) func(ops.Call) (*ops.Answer, error) {
	return func(c ops.Call) (*ops.Answer, error) {
		id := c.Args.Text("id")
		if !proofstore.ValidID(id) {
			return nil, &ops.Refusal{Reason: "a proof's id is 24 hexadecimal characters"}
		}
		e, err := src.Get(id)
		if err != nil {
			return nil, &ops.Refusal{Reason: err.Error()}
		}
		row := entryRow(e)
		if e.Broken != "" {
			return row, nil
		}
		st := e.Statement
		p := st.Predicate
		words := wordsFrom(st)
		row.With("verifier", ops.Object().With("id", ops.Ours(p.Verifier.ID)).
			With("version", ops.Ours(p.Verifier.Version)).With("program", ops.Ours(p.Verifier.Program)))
		row.With("checks", ops.ListOf(p.Checks, func(ch proof.Check) *ops.Answer {
			return ops.Object().With("name", ops.Ours(ch.Name)).With("passed", ops.Ours(ch.Passed)).
				With("detail", words(ch.Detail)).With("failures", ops.ListOf(ch.Failures, words))
		}))
		row.With("materials", ops.ListOf(p.Materials, func(m proof.Material) *ops.Answer {
			return ops.Object().With("name", words(m.Name)).With("sha256", ops.Ours(m.Digest["sha256"])).
				With("entries", ops.Ours(m.Entries))
		}))
		switch {
		case p.Detection != nil:
			d := p.Detection
			row.With("evidence", ops.Object().With("rule", ops.Outside(d.Rule)).
				With("positives", ops.Ours(d.Positives)).With("caught", ops.Ours(d.Caught)).
				With("negatives", ops.Ours(d.Negatives)).With("quiet", ops.Ours(d.Quiet)).
				With("recall_wilson_low", ops.Ours(d.RecallLow)).
				With("specificity_wilson_low", ops.Ours(d.SpecificityLow)).
				With("fixtures", ops.Ours(d.Fixtures)))
		case p.Calibration != nil:
			k := p.Calibration
			row.With("evidence", ops.Object().With("model", ops.Ours(k.Model)).
				With("family", ops.Ours(k.Family)).With("channel", ops.Ours(k.Channel)).
				With("threshold", ops.Ours(k.Threshold)).With("epsilon", ops.Ours(k.Epsilon)).
				With("delta", ops.Ours(k.Delta)).With("cases", ops.Ours(k.Cases)).
				With("closures", ops.Ours(k.Closures)).With("false_closures", ops.Ours(k.FalseClosures)).
				With("false_closure_upper", ops.Ours(k.Upper)).With("expires", ops.Ours(k.Expires)).
				With("template_sha256", ops.Ours(k.Template)))
		case p.NotAffected != nil:
			v := p.NotAffected
			reasons := ops.List()
			for _, r := range v.Reasons {
				reasons.Add(ops.Object().With("reason", ops.Ours(r.Reason)).With("count", ops.Ours(r.Count)))
			}
			row.With("evidence", ops.Object().With("source", ops.Ours(v.Source)).
				With("asset", ops.Ours(v.Asset)).With("statements", ops.Ours(v.Statements)).
				With("not_affected", ops.Ours(v.NotAffected)).With("supported", ops.Ours(v.Supported)).
				With("contradicted", ops.Ours(v.Contradicted)).With("uncheckable", ops.Ours(v.Uncheckable)).
				With("reasons", reasons))
		case p.ClaimTest != nil:
			v := p.ClaimTest
			row.With("evidence", ops.Object().With("card", ops.Ours(v.Name)).
				With("source", ops.Ours(v.Source)).With("metric", ops.Ours(v.Metric)).
				With("direction", ops.Ours(v.Direction)).With("threshold", ops.Ours(v.Threshold)).
				With("confidence", ops.Ours(v.Confidence)).With("window_closed", ops.Ours(v.Closed)).
				With("count", ops.Object().With("k", ops.Ours(v.K)).With("n", ops.Ours(v.N)).
					With("lower", ops.Ours(v.Low)).With("upper", ops.Ours(v.High))))
		case p.Adjudication != nil:
			v := p.Adjudication
			bound := func(b proof.Bound) *ops.Answer {
				return ops.Object().With("k", ops.Ours(b.K)).With("n", ops.Ours(b.N)).
					With("lower", ops.Ours(b.Lower)).With("upper", ops.Ours(b.Upper))
			}
			row.With("evidence", ops.Object().With("source", ops.Ours(v.Source)).
				With("sample", ops.Ours(v.Sample)).With("committed_at_entry", ops.Ours(int(v.Committed.Seq))).
				With("tolerance", ops.Ours(v.Tolerance)).
				With("ai_false_closures", bound(v.AI)).With("human_false_closures", bound(v.Human)).
				With("population_ai", ops.Ours(v.PopulationAI)).
				With("population_human", ops.Ours(v.PopulationHuman)).
				With("reviewers", ops.Ours(v.Reviewers)).With("earlier_draws", ops.Ours(v.EarlierDraws)))
		case p.Reconciliation != nil:
			v := p.Reconciliation
			row.With("evidence", ops.Object().With("agent", ops.Ours(v.Agent)).
				With("telemetry_agent", ops.Ours(v.Telemetry)).
				With("since", ops.Ours(v.Since)).With("until", ops.Ours(v.Until)).
				With("window_seconds", ops.Ours(v.Window)).
				With("reported", ops.Ours(v.Reported)).With("calls", ops.Ours(v.Calls)).
				With("matched", ops.Ours(v.Matched)).With("unreported", ops.Ours(v.Unreported)).
				With("unreceived", ops.Ours(v.Unreceived)).With("connections", ops.Ours(v.Connects)).
				With("unexplained", ops.Ours(v.Unexplained)).
				With("shared_skipped", ops.Ours(v.SharedSkipped)))
		case p.Verdicts != nil:
			v := p.Verdicts
			count := func(k, n int) *ops.Answer { return ops.Object().With("k", ops.Ours(k)).With("n", ops.Ours(n)) }
			row.With("evidence", ops.Object().With("source", ops.Ours(v.Source)).
				With("labels", ops.Ours(v.Labels)).With("since", ops.Ours(v.Since)).With("until", ops.Ours(v.Until)).
				With("tolerance", ops.Ours(v.Tolerance)).
				With("false_closures", count(v.FalseClosures.K, v.FalseClosures.N).
					With("lower", ops.Ours(v.FalseClosures.Lower)).With("upper", ops.Ours(v.FalseClosures.Upper))).
				With("review_coverage", count(v.ReviewCoverage.K, v.ReviewCoverage.N)).
				With("delivered_before_disposition", count(v.DeliveredFirst.K, v.DeliveredFirst.N)).
				With("agreement", count(v.Agreement.K, v.Agreement.N)).
				With("escalations_closed", count(v.EscalationsClosed.K, v.EscalationsClosed.N)).
				With("abstentions", count(v.Abstentions.K, v.Abstentions.N)).
				With("consistency", count(v.Consistency.K, v.Consistency.N)))
		}
		return row, nil
	}
}

func keepProof(root string) func(ops.Call) (*ops.Answer, error) {
	return func(c ops.Call) (*ops.Answer, error) {
		id, st, err := proofstore.Keep(root, []byte(c.Args.Text("envelope")),
			[]byte(c.Args.Text("public_key")), c.Caller.Name(), proofstore.OriginHandedIn, c.Now)
		already := errors.Is(err, proofstore.ErrAlreadyKept)
		if err != nil && !already {
			return nil, &ops.Refusal{Reason: err.Error()}
		}
		return ops.Object().With("id", ops.Ours(id)).With("kind", ops.Ours(proofKind(st))).
			With("verdict", ops.Ours(string(st.Predicate.Verdict))).With("already_kept", ops.Ours(already)), nil
	}
}

// Ops is the proving ground's registry for the store at root: the reads, and
// keeping a proof.
func Ops(root string) *ops.Registry {
	r := ops.NewRegistry()
	addReads(r, Store(root))
	r.Add(keepOp(root))
	return r
}

// ReadOps is the proving ground's reads over src alone: what a recorded case
// can answer, with nothing to change.
func ReadOps(src Source) *ops.Registry {
	r := ops.NewRegistry()
	addReads(r, src)
	return r
}

func addReads(r *ops.Registry, src Source) {
	r.Add(ops.Op{Name: "list_proofs", CLI: "proof list",
		Summary: "the proofs kept here: what was proven, refuted or left inconclusive",
		Detail: "Newest first. Each says whose key signed it and whether it still " +
			"verifies; one that no longer does is listed as broken, never as what it now says.",
		Needs: auth.ActView, Area: auth.AreaSecurity, Effect: ops.Read,
		Args: []ops.Arg{
			{Name: "kind", Kind: ops.Text, About: "only this kind: " + strings.Join(kindWords, ", ")},
			{Name: "limit", Kind: ops.Number, About: "how many to show, at most 500 (default 50)"},
		},
		Keywords: []string{"proof", "proofs", "verdict", "certificate", "calibration", "scorecard", "proven", "refuted"},
		Run:      listProofs(src)})
	r.Add(ops.Op{Name: "read_proof", CLI: "proof show",
		Summary: "one kept proof: its claim, checks, evidence and materials",
		Needs:   auth.ActView, Area: auth.AreaSecurity, Effect: ops.Read,
		Args: []ops.Arg{{Name: "id", Kind: ops.Text, Required: true, Positional: true,
			About: "the proof's id, as list_proofs gives it"}},
		Keywords: []string{"proof", "evidence", "checks", "claim"},
		Run:      readProof(src)})
}

func keepOp(root string) ops.Op {
	return ops.Op{Name: "keep_proof", CLI: "proof keep",
		Summary: "keep a proof made elsewhere, after checking it against its public key",
		Needs:   auth.ActTriage, Area: auth.AreaSecurity, Effect: ops.Change, Audit: "proof.kept",
		Args: []ops.Arg{
			{Name: "envelope", Kind: ops.Document, Required: true, Positional: true, Max: proof.MaxEnvelope,
				About: "the signed proof (a DSSE envelope)"},
			{Name: "public_key", Kind: ops.Document, Required: true, Max: 64 << 10,
				About: "the public key that signed it"},
		},
		Run: keepProof(root)}
}
