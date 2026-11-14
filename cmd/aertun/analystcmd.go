// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/analyst"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/decide"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/model"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/pii"
	"github.com/aertun/aertun/internal/proof"
)

// The analyst: a model's first pass over the queue, as suggestions.
//
// `analyst triage` takes the open findings nobody has looked at, carries
// out the fixed plan in internal/analyst for each, and writes what it
// concluded as a proposal — the same record an outside agent writes through
// propose_finding_decision, shown on the finding's page for a person to
// agree with or not. It has no other way to write: this file calls the
// audit log for a proposal and nothing that records a decision.
//
// `analyst eval` measures the model that is configured, on this
// organisation's own history: the findings people have ruled on, each run
// several times, and again with instructions planted in the log text.
//
// triageAgent is the name the analyst acts under.
const triageAgent = "analyst:triage"

// abstainAction records that the analyst looked and had no suggestion, so
// the same finding is not put to the model again until it changes.
const abstainAction = "analyst.abstained"

// unusableAction records that the model could not be asked — the endpoint
// was down, timed out, or answered nothing that parsed. That is a fact
// about the model and not a judgement about the finding, so the record
// carries no "seen" and alreadyLooked passes it by: the finding is asked
// again on the next run, not hidden because the endpoint was broken once.
const unusableAction = "analyst.model-unusable"

// modelUnusable is abstainWord's word for the endpoint, rather than the
// finding, being why there is no suggestion.
const modelUnusable = "the model could not be used"

func agentsDir(root string) string { return filepath.Join(root, "agents") }

// analystModel is the model a triage asks, behind the privacy guard:
// personal data reaches it only when it is on this organisation's network,
// and what was masked is recorded as counts.
func analystModel(root string) (decide.Model, string) {
	m, err := model.NewHTTPModel()
	if err != nil {
		return nil, "no model is configured: " + firstLine(err)
	}
	meter := &usageMeter{}
	m.OnUsage = meter.add
	host := ""
	if u, err := url.Parse(m.BaseURL); err == nil {
		host = u.Hostname()
	}
	return metered{Model: model.Guarded{Model: m, Personal: hostIsLocal(host),
		OnMasked: func(counts map[string]int) { noteMasked(root, triageAgent, host, counts) }},
		meter: meter}, ""
}

// usageMeter adds up what the model used across a run, and brackets each
// finding's questions so a proposal can say what it cost. Estimates and
// reports are kept apart: a provider that says nothing is counted, but the
// record says estimated rather than passing a guess off as a measurement.
type usageMeter struct {
	in, out      int
	measured     bool
	anyEstimated bool

	curIn, curOut int
	curMeasured   bool
	inCurrent     bool
}

func (u *usageMeter) add(m model.Usage) {
	if u.inCurrent {
		u.curIn += m.In
		u.curOut += m.Out
		u.curMeasured = u.curMeasured && m.Reported
	}
	u.in += m.In
	u.out += m.Out
	u.measured = u.measured || m.Reported
	u.anyEstimated = u.anyEstimated || !m.Reported
}

// begin opens the bracket for one finding's questions.
func (u *usageMeter) begin() { u.curIn, u.curOut, u.curMeasured, u.inCurrent = 0, 0, true, true }

// take closes the bracket and returns what the finding's questions used.
func (u *usageMeter) take() (in, out int, measured bool) {
	u.inCurrent = false
	return u.curIn, u.curOut, u.curMeasured
}

// metered carries the meter beside the model, so runTriage can bracket
// each finding without knowing whether the model reports usage at all: a
// test's stub does not implement the interface, and the assertions simply
// find nothing.
type metered struct {
	decide.Model
	meter *usageMeter
}

// BeginUsage opens the bracket for one finding's questions.
func (m metered) BeginUsage() { m.meter.begin() }

// TakeUsage closes the bracket for one finding's questions.
func (m metered) TakeUsage() (in, out int, measured bool) { return m.meter.take() }

// CompleteReply passes decide's request for token probabilities through to
// the model when it can return them, so wrapping the model for its meter
// does not hide that channel; a model that cannot is asked the plain way.
func (m metered) CompleteReply(ctx context.Context, system, user string,
	p model.Params) (model.Reply, error) {

	if rm, ok := m.Model.(model.Replier); ok {
		return rm.CompleteReply(ctx, system, user, p)
	}
	out, err := m.Model.Complete(ctx, system, user)
	return model.Reply{Text: out, Raw: out}, err
}

// usaged is what runTriage asks of its model: can it account for itself?
type usaged interface {
	BeginUsage()
	TakeUsage() (in, out int, measured bool)
}

// noteMasked records what was taken out of a prompt before it left, as
// counts: the record that personal data stayed here, which names none of
// it.
func noteMasked(root, caller, host string, counts map[string]int) {
	d := map[string]string{"caller": caller, "host": host}
	for k, n := range counts {
		// The log refuses a key that names a secret, and with it the
		// whole record: a credential is counted under another name.
		if k == string(pii.Secret) {
			k = "credential"
		}
		d["masked_"+k] = strconv.Itoa(n)
	}
	record(root, audit.Record{Action: "model.masked", Resource: "/analyst", Outcome: audit.Success,
		Principal: "aertun", Kind: audit.KindService, Verified: true, Detail: d})
}

// hostIsLocal is this machine or a private network: somewhere what is sent
// does not leave the organisation.
func hostIsLocal(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// analystSeam lets a test stand in for the model.
var analystSeam func(root string) (decide.Model, string)

func modelForAnalyst(root string) (decide.Model, string) {
	if analystSeam != nil {
		return analystSeam(root)
	}
	return analystModel(root)
}

func cmdAnalyst(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"plan"}
	}
	switch args[0] {
	case "plan":
		return analystPlan()
	case "triage":
		return analystTriage(root, args[1:])
	case "eval":
		return analystEval(root, args[1:])
	case "calibrate":
		return analystCalibrate(root, args[1:])
	default:
		return fmt.Errorf("unknown analyst command %q; try plan, triage, "+
			"eval or calibrate", args[0])
	}
}

func analystPlan() error {
	if w.JSON(map[string]any{"plan": analyst.TriagePlan,
		"decider": analyst.Decider()}) {
		return nil
	}
	w.Human("%sWhat a triage reads, in order%s\n\n", bold, reset)
	for n, s := range analyst.TriagePlan {
		mark := ""
		if s.Untrusted {
			mark = "  " + yellow + "text somebody else wrote" + reset
		}
		w.Human("%s%d.%s %s%s%s: %s%s\n", dim, n+1, reset, bold, s.Name,
			reset, s.Reads, mark)
	}
	w.Human("\n  %sthe list is fixed before anything is read, and what "+
		"comes out is a suggestion a person agrees with or not%s\n", dim,
		reset)
	return nil
}

// alreadyLooked is the findings the analyst has been through, and how
// many times each had been seen when it was.
func alreadyLooked(events []audit.Event) map[string]string {
	out := map[string]string{}
	for _, e := range events {
		if e.Detail["agent"] != "triage" {
			continue
		}
		if e.Action == finding.ProposalAction || e.Action == abstainAction {
			out[e.Detail["finding"]] = e.Detail["seen"]
		}
	}
	return out
}

// incidentFindings is every finding an incident gathers.
func incidentFindings(root string) (map[string]bool, error) {
	all, err := listIncidents(root)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, i := range all {
		for _, f := range i.Findings {
			out[f] = true
		}
	}
	return out, nil
}

// indicatorFeeds is how many feeds list each indicator a queue's findings
// came from, by the indicator's id — read only when some finding is an
// indicator's, so a queue of rule findings pays nothing for the store.
//
// Facts' volume group carries Sources, and volume is the class whoever is
// being detected can shape, so where the number comes from matters all
// the more: it is read from the indicators themselves, which the finding
// carries only by id. A title names the feeds in prose, and whoever named
// a feed — "spam and eggs" would count for two, read out of a title —
// must not be able to move it.
func indicatorFeeds(root string, q []finding.Finding) (map[string]int, error) {
	fromIntel := false
	for _, f := range q {
		if strings.HasPrefix(f.Source, "intel/") {
			fromIntel = true
			break
		}
	}
	if !fromIntel {
		return nil, nil
	}
	set, err := loadIndicators(root)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, i := range set.All() {
		out[i.ID] = len(i.Sources)
	}
	return out, nil
}

// gatherState carries out the plan for one finding and finishes the facts
// the finding cannot give itself: how many feeds listed the indicator it
// came from, which Gather knows better than to read out of a title.
func gatherState(f finding.Finding, all []finding.Finding, inIncident bool,
	now time.Time, feeds map[string]int) (analyst.State, []analyst.Trace) {

	st, trace := analyst.Gather(f, all, inIncident, now)
	if st.Facts.Indicator {
		st.Facts.Volume.Sources = feeds[strings.TrimPrefix(f.Source, "intel/")]
	}
	return st, trace
}

// triageOutcome is what happened to one finding.
type triageOutcome struct {
	Finding string `json:"finding"`
	analyst.Suggestion
	// Cost is what asking this finding used, when the model can account
	// for itself; nil for a stub that cannot.
	Cost *triageCost `json:"cost,omitempty"`
}

// triageCost is the tokens one finding's questions used. Measured is the
// provider's own accounting; without it the numbers are an estimate and
// are labelled as one wherever they are shown.
type triageCost struct {
	In, Out  int
	Measured bool
}

// tokens returns the cost as audit detail values, or nil when the model
// said nothing and an estimate is not worth a record.
func (c *triageCost) tokens() map[string]string {
	if c == nil || !c.Measured {
		return nil
	}
	// "used", not "tokens": the log refuses a detail key shaped like a
	// credential, and "token" is the part that matches.
	return map[string]string{
		"used_in":  strconv.Itoa(c.In),
		"used_out": strconv.Itoa(c.Out),
	}
}

// runTriage is the analyst's pass. on is who asked for it. cal is a
// calibration certificate offered to the gate, or nil for the declared
// threshold.
func runTriage(ctx context.Context, root string, caller *Caller, limit int,
	dry bool, now time.Time, cal *decide.Calibration) ([]triageOutcome, int, error) {

	if caller.Kind == audit.KindAI {
		return nil, 0, fmt.Errorf("the analyst is started by a person. A " +
			"model starting a model is a loop with nobody in it")
	}
	m, why := modelForAnalyst(root)
	if m == nil {
		return nil, 0, fmt.Errorf("%s", why)
	}
	q, err := loadQueue(root, now)
	if err != nil {
		return nil, 0, err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, 0, err
	}
	looked := alreadyLooked(events)
	gathered, err := incidentFindings(root)
	if err != nil {
		return nil, 0, err
	}
	feeds, err := indicatorFeeds(root, q)
	if err != nil {
		return nil, 0, err
	}
	var out []triageOutcome
	waiting := 0
	for _, f := range q {
		if f.State != finding.Open {
			continue
		}
		seen := fmt.Sprint(f.Seen)
		if looked[f.ID] == seen {
			// Looked at, and nothing about it has changed since.
			continue
		}
		if len(out) >= limit {
			waiting++
			continue
		}
		state, trace := gatherState(f, q, gathered[f.ID], now, feeds)
		var cost *triageCost
		if um, ok := m.(usaged); ok {
			um.BeginUsage()
		}
		s, terr := analyst.AskWith(ctx, m, state, trace, cal)
		if terr != nil {
			return out, waiting, fmt.Errorf("%s: %w", f.ID, terr)
		}
		if um, ok := m.(usaged); ok {
			var c triageCost
			c.In, c.Out, c.Measured = um.TakeUsage()
			cost = &c
		}
		out = append(out, triageOutcome{f.ID, s, cost})
		if dry {
			continue
		}
		if s.To == "" && abstainWord(s.Abstained) == modelUnusable {
			// Infrastructure, not a verdict: no abstain-with-seen, so the
			// next pass asks again rather than taking an outage for an
			// answer. What happened is still on the record.
			if err := recordE(root, audit.Record{Action: unusableAction,
				Resource: "/" + f.ID, Outcome: audit.Success,
				Principal: triageAgent, Kind: audit.KindAI, Model: m.Name(),
				Verified: false,
				Detail: map[string]string{"finding": f.ID, "agent": "triage",
					"on_behalf_of": caller.Name}}); err != nil {
				return out, waiting, err
			}
			continue
		}
		rec := audit.Record{Action: abstainAction, Resource: "/" + f.ID,
			Outcome:   audit.Success,
			Principal: triageAgent, Kind: audit.KindAI, Model: m.Name(),
			Verified: false,
			Detail: map[string]string{"finding": f.ID, "agent": "triage",
				"seen": seen, "on_behalf_of": caller.Name,
				"confidence": fmt.Sprintf("%.2f", s.Confidence)}}
		for k, v := range cost.tokens() {
			rec.Detail[k] = v
		}
		// What the model was shown as counts and closed-set words, kept
		// beside its answer so `forge export` can say exactly what it saw
		// rather than rebuild it from a register that has moved on since.
		for k, v := range sawDetail(state.Facts) {
			rec.Detail[k] = v
		}
		if cal != nil && s.Threshold > 0 {
			// Which gate the answer met, from decide's own account: a
			// suggestion let through by a certified threshold reads
			// differently on the record from one the declared threshold
			// let through.
			rec.Detail["threshold"] = fmt.Sprintf("%.2f", s.Threshold)
			rec.Detail["gate"] = map[bool]string{true: "certified", false: "declared"}[s.Certified]
		}
		if s.To != "" {
			rec.Action = finding.ProposalAction
			rec.Detail["to"] = string(s.To)
			rec.Detail["because"] = s.Reason
			if s.CounterfactualChanged {
				rec.Detail["counterfactual"] = "changed"
			}
		} else {
			// A closed set of reasons, not the model's words.
			rec.Detail["why"] = abstainWord(s.Abstained)
		}
		if err := recordE(root, rec); err != nil {
			return out, waiting, err
		}
	}
	return out, waiting, nil
}

// abstainWord reduces why the analyst had no suggestion to one of a few
// words, so nothing a model produced is copied into the log.
func abstainWord(why string) string {
	switch {
	case strings.Contains(why, "calibration certificate"):
		// Usable, and confident or not: held back because the gate it was
		// offered was not one that could certify it. A different lesson
		// from either a weak answer or a missing one.
		return "no certified gate"
	case strings.Contains(why, "threshold"):
		return "not confident enough"
	case strings.Contains(why, "no model"), strings.Contains(why, "could not be used"):
		return modelUnusable
	case why == analyst.CounterfactualUnconfirmed:
		return "did not hold without the attacker's text"
	}
	return "no usable answer"
}

// humanCount is a number the way a person reads one at a glance: small
// counts exact, large ones rounded to where their meaning survives.
func humanCount(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 10_000:
		return fmt.Sprintf("%dk", n/1_000)
	}
	return strconv.Itoa(n)
}

func analystTriage(root string, args []string) error {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	limit := fs.Int("limit", 20, "how many findings to look at")
	dry := fs.Bool("dry-run", false, "look, and record nothing")
	calAt := fs.String("calibration", "", "a signed calibration certificate "+
		"(analyst calibrate writes one) whose threshold gates the suggestions "+
		"in place of the declared one, when it fits this model")
	calKey := fs.String("calibration-key", "", "the public key the "+
		"certificate must be signed by")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *limit < 1 || *limit > 500 {
		return fmt.Errorf("--limit is between 1 and 500")
	}
	if (*calAt == "") != (*calKey == "") {
		return fmt.Errorf("--calibration and --calibration-key go together: a " +
			"certificate is checked against a key you were handed, never one it supplies")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActTriage, auth.AreaSecurity); err != nil {
		return err
	}
	var cal *decide.Calibration
	if *calAt != "" {
		body, err := proof.ReadBounded(*calAt, proof.MaxEnvelope)
		if err != nil {
			return err
		}
		pub, err := pack.LoadPublicKey(*calKey)
		if err != nil {
			return err
		}
		adapter, err := modelAdapter()
		if err != nil {
			return err
		}
		cal = &decide.Calibration{Certificate: body, Key: pub, Adapter: adapter}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	out, waiting, err := runTriage(ctx, root, caller, *limit, *dry,
		time.Now().UTC(), cal)
	if err != nil {
		return err
	}
	suggested := 0
	tokensIn, tokensOut := 0, 0
	for _, o := range out {
		if o.To != "" {
			suggested++
		}
		if o.Cost != nil {
			tokensIn += o.Cost.In
			tokensOut += o.Cost.Out
		}
	}
	summary := map[string]any{"looked": len(out), "suggested": suggested,
		"waiting": waiting, "dry_run": *dry, "findings": out}
	if tokensIn > 0 || tokensOut > 0 {
		summary["used_in"], summary["used_out"] = tokensIn, tokensOut
	}
	if w.JSON(summary) {
		return nil
	}
	if tokensIn > 0 || tokensOut > 0 {
		w.Human("  %stokens used: %s in / %s out%s\n", dim,
			humanCount(tokensIn), humanCount(tokensOut), reset)
	}
	if len(out) == 0 {
		w.Human("Nothing open that the analyst has not already looked at.\n")
		return nil
	}
	for _, o := range out {
		if o.To == "" {
			w.Human("  %s%s%s  no suggestion: %s\n", dim, o.Finding, reset,
				abstainWord(o.Abstained))
			continue
		}
		w.Human("  %s%s%s  suggests %s%s%s at %.2f\n", dim, o.Finding, reset,
			bold, o.To, reset, o.Confidence)
	}
	w.Human("\n%s%d looked at, %d suggestion(s)%s", bold, len(out), suggested,
		reset)
	if waiting > 0 {
		w.Human(", %d more waiting", waiting)
	}
	w.Human("\n")
	if cal != nil {
		w.Human("  %s%s%s\n", dim, gateLine(out), reset)
	}
	if *dry {
		w.Human("  %sa dry run: nothing was recorded%s\n", dim, reset)
	} else {
		w.Human("  %snothing has changed state. Each suggestion is on its "+
			"finding's page for a person to agree with or not%s\n", dim, reset)
	}
	return nil
}

// gateLine says what became of the calibration certificate a run was
// offered, from decide's own account on each answer: used, or refused and
// why — one of calib's closed set of reasons — and in either case how many
// answers met a certified threshold.
func gateLine(out []triageOutcome) string {
	status, certified := "", 0
	for _, o := range out {
		if o.Certificate != "" {
			status = o.Certificate
		}
		if o.Certified {
			certified++
		}
	}
	switch {
	case status == "":
		return "the calibration certificate was not consulted: the model gave no answer to gate"
	case status == decide.CertificateUsed:
		return fmt.Sprintf("the calibration certificate set the gate; %d of %d "+
			"answer(s) were held to its threshold, and any other went to a "+
			"person because it was not scored on the certificate's channel",
			certified, len(out))
	}
	return "the calibration certificate was " + status + ", so every answer " +
		"went to a person"
}

// ruledCase is one finding people have ruled on, with the moment its
// verdict was recorded: the moment its case has to be gathered as of.
type ruledCase struct {
	f      finding.Finding
	expect string
	at     time.Time
}

// verdictCases turns what people have ruled into cases: each finding as
// the analyst would have seen it WHEN ITS VERDICT WAS RECORDED, not as the
// register stands now. Gathered over today's register, the counts for a
// finding decided on Monday include Tuesday's verdicts — some of which may
// exist because the analyst itself suggested them — and the eval would
// measure the model against information it never had, with pass^k to match.
// The register is a fold of the audit log, so the past is rebuilt rather
// than guessed: decisions recorded after the moment are left out of the
// fold, and so are findings first reported after it.
//
// limit caps the work without deciding what is measured: every ruled
// finding is a candidate, and when there are more than limit the three
// verdicts are taken round-robin, oldest verdict first within each. The
// first N by rank — what taking the head of the queue was — are the severe
// N, and a model measured on the severe N has been measured on a queue
// this organisation does not have.
func verdictCases(reg *finding.Register, events []audit.Event,
	feeds map[string]int, limit int) []analyst.Case {

	decisions := finding.FromAudit(events)
	now := time.Now().UTC()
	// Fixed order, so the round-robin deals the same hand twice running.
	classes := []string{analyst.Real, analyst.FalsePositive, analyst.Benign}
	var byClass [3][]ruledCase
	for _, f := range reg.All(now) {
		// The register arrives unfolded — the eval reads the pieces, so
		// each case can be folded again as of its own verdict — so the
		// state a finding ended in is the decisions folded onto it, not
		// the open shape it is stored in.
		ruled := finding.Apply(f, decisions)
		var expect string
		switch ruled.State {
		case finding.Triaged, finding.Fixed, finding.Accepted:
			expect = analyst.Real
		case finding.FalsePositive:
			expect = analyst.FalsePositive
		case finding.Benign:
			expect = analyst.Benign
		default:
			continue
		}
		h := finding.History(f.ID, decisions)
		if len(h) == 0 {
			// Ruled, with no record this can date: it cannot be placed in
			// time, and a case that cannot be dated cannot be gathered
			// honestly.
			continue
		}
		for i, name := range classes {
			if name == expect {
				byClass[i] = append(byClass[i],
					ruledCase{f: f, expect: expect, at: h[len(h)-1].At})
			}
		}
	}
	for i := range byClass {
		sort.Slice(byClass[i], func(a, b int) bool {
			return byClass[i][a].at.Before(byClass[i][b].at)
		})
	}
	total := len(byClass[0]) + len(byClass[1]) + len(byClass[2])
	picked := make([]ruledCase, 0, total)
	if total <= limit {
		for _, class := range byClass {
			picked = append(picked, class...)
		}
	} else {
		for len(picked) < limit {
			dealt := false
			for i := range byClass {
				if len(picked) == limit || len(byClass[i]) == 0 {
					continue
				}
				picked = append(picked, byClass[i][0])
				byClass[i] = byClass[i][1:]
				dealt = true
			}
			if !dealt {
				break
			}
		}
	}

	var out []analyst.Case
	for _, rc := range picked {
		asOf := registerAsOf(reg, decisions, rc.at)
		incidents := incidentsAsOf(events, rc.at)
		st, _ := gatherState(rc.f, asOf, incidents[rc.f.ID], rc.at, feeds)
		out = append(out, analyst.Case{Name: rc.f.ID, State: st,
			Expect: rc.expect})
	}
	return out
}

// registerAsOf is the register as it stood at t: the findings the register
// holds, with only the decisions recorded before t folded onto them, and
// without the findings first reported after it. Rebuilt rather than
// remembered because the audit log is the only place a decision's moment
// is kept.
//
// What stays the register's present: a finding's Seen count and its
// retained evidence are the register file's current shape, which the log
// cannot re-derive. Those are the scanner's numbers, not people's; the
// verdicts are the part that could leak the future into a measurement,
// and the verdicts are as-of.
func registerAsOf(reg *finding.Register, decisions []finding.Decision,
	t time.Time) []finding.Finding {
	var before []finding.Decision
	for _, d := range decisions {
		if d.At.Before(t) {
			before = append(before, d)
		}
	}
	var out []finding.Finding
	for _, f := range reg.All(t) {
		if f.First.After(t) {
			continue
		}
		out = append(out, finding.Apply(f, before))
	}
	return out
}

// incidentsAsOf is which findings an incident had gathered by t, folded
// from the audit log's link and unlink records. A finding linked while the
// incident was being declared is read as not linked: the declared record
// carries a count, not the ids. That understates what the analyst had and
// never states what it did not — the wrong side for a measurement to err
// on is the side that measures the future.
func incidentsAsOf(events []audit.Event, t time.Time) map[string]bool {
	out := map[string]bool{}
	for _, e := range events {
		at, err := time.Parse(time.RFC3339Nano, e.At)
		if err != nil || !at.Before(t) {
			continue
		}
		switch e.Action {
		case "incident.link":
			if f := e.Detail["finding"]; f != "" {
				out[f] = true
			}
		case "incident.unlink":
			delete(out, e.Detail["finding"])
		}
	}
	return out
}

func analystEval(root string, args []string) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	k := fs.Int("k", 3, "how many times each case is run")
	limit := fs.Int("limit", 50, "how many ruled findings to measure, "+
		"spread across the three verdicts when there are more")
	file := fs.String("cases", "", "cases from a file, one JSON object "+
		"per line, instead of the findings people have ruled on")
	if err := fs.Parse(args); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	m, why := modelForAnalyst(root)
	if m == nil {
		return fmt.Errorf("%s", why)
	}
	now := time.Now().UTC()
	var cases []analyst.Case
	if *file != "" {
		err := loadJSONL(*file, func(b []byte) error {
			var c analyst.Case
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			cases = append(cases, c)
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		// The register and the log rather than loadQueue's folded view:
		// each case has to be folded again, as of its own verdict's
		// moment, and that needs the pieces rather than the result.
		reg, _, err := finding.Load(findingsPath(root))
		if err != nil {
			return err
		}
		events, err := audit.Read(auditPath(root))
		if err != nil {
			return err
		}
		feeds, err := indicatorFeeds(root, reg.All(now))
		if err != nil {
			return err
		}
		cases = verdictCases(reg, events, feeds, *limit)
		if len(cases) == 0 {
			return fmt.Errorf("nobody has ruled on a finding yet, so there " +
				"is nothing to measure the analyst against. Rule on some, " +
				"or give --cases FILE")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	rep, err := analyst.Evaluate(ctx, m, cases, *k)
	if err != nil {
		return err
	}
	record(root, audit.Record{Action: "analyst.evaluated", Resource: "/agents",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind, Model: caller.Model,
		Verified: caller.Verified, Detail: map[string]string{
			"cases": fmt.Sprint(rep.Cases), "k": fmt.Sprint(rep.K),
			"reliable": fmt.Sprint(rep.Reliable), "wrong": fmt.Sprint(rep.Wrong),
			"hijacked": fmt.Sprint(rep.Hijacked), "model": m.Name()}})
	if w.JSON(rep) {
		return nil
	}
	w.Human("%s%d case(s), each run %d time(s)%s, on %s\n\n", bold, rep.Cases,
		rep.K, reset, m.Name())
	w.Human("  %s%d reliable%s: right on every run (pass^%d = %.0f%%)\n",
		green, rep.Reliable, reset, rep.K, rep.PassK*100)
	w.Human("  %s%d abstained%s: never wrong, and left some to a person\n",
		dim, rep.Abstained, reset)
	colour := dim
	if rep.Wrong > 0 {
		colour = red
	}
	w.Human("  %s%d wrong%s: confidently suggested something a person ruled "+
		"otherwise\n", colour, rep.Wrong, reset)
	for _, n := range rep.WrongCases {
		w.Human("      %s%s%s\n", dim, n, reset)
	}
	colour = dim
	if rep.Hijacked > 0 {
		colour = red
	}
	w.Human("\n  %s%d of %d hijacked%s: text planted where a log's text goes "+
		"moved the suggestion to what it asked for\n", colour, rep.Hijacked,
		rep.Planted, reset)
	for _, n := range rep.HijackedCases {
		w.Human("      %s%s%s\n", dim, n, reset)
	}
	w.Human("\n  %seven hijacked, the analyst can only suggest: a person "+
		"records every verdict%s\n", dim, reset)
	return nil
}

// ---- agents as a log source -------------------------------------------------

// agentsSeen is what has been observed of the agents so far.
type agentsSeen struct {
	// Seq is the last audit entry read.
	Seq int64 `json:"seq"`
	// Did is each agent's actions, and First when it was first seen.
	Did   map[string][]string  `json:"did"`
	First map[string]time.Time `json:"first"`
}

func agentsSeenPath(root string) string {
	return filepath.Join(agentsDir(root), "observed.json")
}
