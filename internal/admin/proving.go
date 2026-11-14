// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/ops"
)

// The proving ground: what AI work, and the rules and verdicts people rely
// on, has been checked against evidence it did not write, and what came of
// it.
//
// These screens are the console's face of internal/ops. They run the same
// operations the command line and the agent interface run, through the same
// Invoke, which asks this console whether the person may and refuses a
// change asked for by an agent; and they show each value as the operation
// labelled it, so text that came from outside is marked here exactly where
// the agent interface labels it.

// ProvingGround is what the proving ground's screens need from whoever holds
// the store.
type ProvingGround struct {
	Ops *ops.Registry
	// Record writes an audit record in by's name and fails when it cannot:
	// a change made through these screens is not made without one.
	Record func(by, action, resource string, detail map[string]string) error
}

// decide is whether p may take act on resource: the credential's own limits
// first, then the policy. It renders nothing, for a caller that is not a
// page.
func (s *Server) decide(p principal, act auth.Action, resource string) error {
	d := s.Policy.Evaluate(p.Name, act, resource)
	if err := auth.CheckGranted(d, p.Role, p.Scope, p.Limits, act, resource); err != nil {
		return err
	}
	if !d.Allowed {
		return errors.New(d.Reason)
	}
	return nil
}

// consoleCaller is a person signed in to the console, as internal/ops asks
// about them.
type consoleCaller struct {
	s *Server
	p principal
}

func (c consoleCaller) Allowed(act auth.Action, area string) error { return c.s.decide(c.p, act, area) }

// Agent is a credential that acts for an agent: an on-behalf-of token, which
// names the agent last in its chain. A session a person signed in to with
// their passkey carries no chain.
func (c consoleCaller) Agent() bool  { return len(c.p.Proof.Act) > 0 }
func (c consoleCaller) Name() string { return c.p.Name }
func (c consoleCaller) Record(action string, d map[string]string) error {
	if c.s.Proving == nil || c.s.Proving.Record == nil {
		return errors.New("this build was started without a record to write")
	}
	return c.s.Proving.Record(c.p.Name, action, "/proving", d)
}

// fact is one value as a screen shows it: its text, and whether somebody
// outside this program could have written it.
type fact struct {
	Text    string
	Outside bool
}

func factOf(a *ops.Answer) fact { return fact{Text: a.Text(), Outside: a.IsOutside()} }

// invokeOp runs an operation for the person behind r, rendering the refusal
// or the failure itself; ok is false when it has.
func (s *Server) invokeOp(w http.ResponseWriter, r *http.Request, p principal, name string,
	args map[string]string) (*ops.Answer, bool) {

	if s.Proving == nil || s.Proving.Ops == nil {
		s.render(w, r, "message.html", map[string]any{"Status": http.StatusServiceUnavailable,
			"Title": "Unavailable", "Principal": p, "Heading": "The proving ground is not available",
			"Body": "This build was started without the proving ground's operations."})
		return nil, false
	}
	a, err := s.Proving.Ops.Invoke(name, consoleCaller{s, p}, args, time.Now().UTC())
	switch {
	case err == nil:
		return a, true
	case ops.IsRefusal(err):
		s.render(w, r, "message.html", map[string]any{"Status": http.StatusForbidden,
			"Title": "Not permitted", "Principal": p, "Heading": "That was refused",
			"Body": err.Error()})
	default:
		s.render(w, r, "message.html", map[string]any{"Status": http.StatusInternalServerError,
			"Title": "Something went wrong", "Principal": p, "Heading": "That could not be done",
			"Body": err.Error()})
	}
	return nil, false
}

// proofRow is one kept proof on the list.
type proofRow struct {
	ID, Kind, Verdict, Tone, KeptAt, KeptBy, Origin, KeyID, Signer, Expires, Broken string
	Subject, Claim                                                                  fact
	Expired                                                                         bool
}

// verdictTone is the colour word a verdict is shown in, beside its name,
// never instead of it.
func verdictTone(v string) string {
	switch v {
	case "proven":
		return "good"
	case "refuted":
		return "serious"
	}
	return "unknown"
}

func (s *Server) handleProofs(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	kind := r.URL.Query().Get("kind")
	args := map[string]string{"limit": "500"}
	if kind != "" {
		args["kind"] = kind
	}
	a, ok := s.invokeOp(w, r, p, "list_proofs", args)
	if !ok {
		return
	}
	now := time.Now().UTC()
	var rows []proofRow
	for _, it := range a.Get("proofs").Items() {
		row := proofRow{ID: it.Get("id").Text(), KeptBy: it.Get("kept_by").Text(),
			Origin: it.Get("origin").Text(), KeyID: it.Get("key_id").Text(), Signer: it.Get("signer").Text()}
		if t, ok := it.Get("kept_at").Value().(time.Time); ok {
			row.KeptAt = t.Format("2 Jan 2006 15:04")
		}
		if b := it.Get("broken"); b != nil {
			row.Broken, row.Tone = b.Text(), "critical"
			rows = append(rows, row)
			continue
		}
		row.Kind, row.Verdict = it.Get("kind").Text(), it.Get("verdict").Text()
		row.Tone = verdictTone(row.Verdict)
		row.Subject, row.Claim = factOf(it.Get("subject")), factOf(it.Get("claim"))
		if e := it.Get("expires"); e != nil {
			row.Expires = e.Text()
			if t, err := time.Parse(time.RFC3339, row.Expires); err == nil {
				row.Expires, row.Expired = t.Format("2 Jan 2006"), !now.Before(t)
			}
		}
		rows = append(rows, row)
	}
	counts := map[string]int{}
	for _, it := range a.Get("by_kind_and_verdict").Keys() {
		n, _ := a.Get("by_kind_and_verdict").Get(it).Value().(int)
		counts[it[strings.IndexByte(it, ' ')+1:]] += n
	}
	broken, _ := a.Get("broken").Value().(int)
	kept, _ := a.Get("kept").Value().(int)
	tiles := []wfTile{
		{Label: "Proven", Value: strconv.Itoa(counts["proven"])},
		{Label: "Refuted", Value: strconv.Itoa(counts["refuted"]), Note: "a check failed, and the proof names what"},
		{Label: "Inconclusive", Value: strconv.Itoa(counts["inconclusive"]), Note: "too little evidence to fail anything"},
		{Label: "No longer verifying", Value: strconv.Itoa(broken), Note: "edited after it was kept"},
	}
	if counts["refuted"] > 0 {
		tiles[1].Tone = "serious"
	}
	if broken > 0 {
		tiles[3].Tone = "critical"
	}
	s.render(w, r, "proofs.html", map[string]any{"Nav": "proofs", "Title": "Proofs",
		"Principal": p, "Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"Rows": rows, "Kept": kept, "Tiles": tiles, "Kind": kind,
		"Kinds": []string{"detection", "triage", "calibration", "verdicts", "reconciliation", "adjudication", "claim", "not-affected", "evidence"}})
}

func (s *Server) handleProof(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	id := strings.TrimPrefix(r.URL.Path, "/proving/proofs/")
	a, ok := s.invokeOp(w, r, p, "read_proof", map[string]string{"id": id})
	if !ok {
		return
	}
	type check struct {
		Name     string
		Passed   bool
		Detail   fact
		Failures []fact
	}
	type material struct {
		Name            fact
		SHA256, Entries string
	}
	type number struct{ Label, Value string }
	data := map[string]any{"Nav": "proofs", "Title": "Proof", "Principal": p,
		"Message": r.URL.Query().Get("m"), "ID": a.Get("id").Text(), "KeptBy": a.Get("kept_by").Text(),
		"Origin": a.Get("origin").Text(), "KeyID": a.Get("key_id").Text(), "Signer": a.Get("signer").Text()}
	if t, ok := a.Get("kept_at").Value().(time.Time); ok {
		data["KeptAt"] = t.Format("2 Jan 2006 15:04 MST")
	}
	if b := a.Get("broken"); b != nil {
		data["Broken"] = b.Text()
		s.render(w, r, "proof.html", data)
		return
	}
	data["Kind"], data["Verdict"] = a.Get("kind").Text(), a.Get("verdict").Text()
	data["Tone"] = verdictTone(a.Get("verdict").Text())
	data["Subject"], data["Claim"] = factOf(a.Get("subject")), factOf(a.Get("claim"))
	data["VerifiedAt"] = a.Get("verified_at").Text()
	v := a.Get("verifier")
	data["Verifier"] = v.Get("id").Text() + " " + v.Get("version").Text()
	var checks []check
	for _, c := range a.Get("checks").Items() {
		ch := check{Name: c.Get("name").Text(), Passed: c.Get("passed").Value() == true,
			Detail: factOf(c.Get("detail"))}
		for _, f := range c.Get("failures").Items() {
			ch.Failures = append(ch.Failures, factOf(f))
		}
		checks = append(checks, ch)
	}
	data["Checks"] = checks
	var mats []material
	for _, m := range a.Get("materials").Items() {
		mats = append(mats, material{Name: factOf(m.Get("name")), SHA256: m.Get("sha256").Text(),
			Entries: m.Get("entries").Text()})
	}
	data["Materials"] = mats
	// The evidence, flattened to label and number, in the order the
	// operation put it: a nested count reads as "k of n".
	var nums []number
	var outsideEvidence []fact
	if ev := a.Get("evidence"); ev != nil {
		for _, k := range ev.Keys() {
			x := ev.Get(k)
			label := strings.ReplaceAll(k, "_", " ")
			switch {
			case x.Leaf() && x.IsOutside():
				outsideEvidence = append(outsideEvidence, fact{Text: label + ": " + x.Text(), Outside: true})
			case x.Leaf():
				nums = append(nums, number{label, x.Text()})
			case x.Get("k") != nil:
				val := x.Get("k").Text() + " of " + x.Get("n").Text()
				if lo := x.Get("lower"); lo != nil {
					val += ", between " + lo.Text() + " and " + x.Get("upper").Text()
				}
				nums = append(nums, number{label, val})
			}
		}
	}
	data["Numbers"], data["OutsideEvidence"] = nums, outsideEvidence
	s.render(w, r, "proof.html", data)
}

// MaxKeptUpload bounds one file handed in through the form.
const MaxKeptUpload = 1 << 20

func (s *Server) handleProofKeep(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	back := func(q url.Values) {
		http.Redirect(w, r, "/proving/proofs?"+q.Encode(), http.StatusSeeOther)
	}
	// A pasted document, or a file; the file wins when both are given.
	field := func(name string) (string, error) {
		if err := r.ParseMultipartForm(MaxRequestBody); err != nil && !errors.Is(err, http.ErrNotMultipart) {
			return "", err
		}
		if f, _, err := r.FormFile(name + "_file"); err == nil {
			defer f.Close()
			b, err := io.ReadAll(io.LimitReader(f, MaxKeptUpload+1))
			if err != nil {
				return "", err
			}
			if len(b) > MaxKeptUpload {
				return "", errors.New("the file is larger than a proof or a key may be")
			}
			return string(b), nil
		}
		return r.FormValue(name), nil
	}
	env, err := field("envelope")
	if err != nil {
		back(url.Values{"e": {err.Error()}})
		return
	}
	pub, err := field("public_key")
	if err != nil {
		back(url.Values{"e": {err.Error()}})
		return
	}
	if s.Proving == nil || s.Proving.Ops == nil {
		back(url.Values{"e": {"This build was started without the proving ground's operations."}})
		return
	}
	a, err := s.Proving.Ops.Invoke("keep_proof", consoleCaller{s, p},
		map[string]string{"envelope": env, "public_key": pub}, time.Now().UTC())
	if err != nil {
		back(url.Values{"e": {err.Error()}})
		return
	}
	msg := "Kept: a " + a.Get("verdict").Text() + " " + a.Get("kind").Text() + " proof."
	if a.Get("already_kept").Value() == true {
		msg = "That proof was already kept."
	}
	http.Redirect(w, r, "/proving/proofs/"+url.PathEscape(a.Get("id").Text())+"?m="+url.QueryEscape(msg),
		http.StatusSeeOther)
}
