// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/adjudicate"
	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/claim"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/ops"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/verdict"
)

// Claim cards: a vendor's claim turned into a test before the data it is
// tested on exists (internal/claim), and signed as a claim proof once its
// window has closed (internal/proof).
//
// `claim register` writes the card — the metric, the product, the alerts it
// counts, the threshold and its direction, the confidence and the window —
// into the store and its digest into the signed audit log; only data that
// arrives after that entry is counted. `claim test` counts the window and
// signs whatever it finds, and says nothing is decided while the window is
// open. A card for adjudicated-false-closures is tested on the one blind
// sample drawn for it after it was registered (`adjudicate draw --claim`).

// claimNow is the clock a test runs on: whether a window has closed is the
// whole question, and a test cannot wait thirty days for it.
var claimNow = time.Now

func claimsDir(root string) string { return filepath.Join(root, "claims") }

func claimPath(root, name string) string { return filepath.Join(claimsDir(root), name+".json") }

const maxClaimFile = 64 << 10

func loadClaim(root, name string) (claim.Card, []byte, error) {
	if !claim.ValidName(name) {
		return claim.Card{}, nil, &ops.Refusal{Reason: "a card's name is 2 to 48 of a-z, 0-9 and -, starting with a letter"}
	}
	body, err := proof.ReadBounded(claimPath(root, name), maxClaimFile)
	if errors.Is(err, os.ErrNotExist) {
		return claim.Card{}, nil, &ops.Refusal{Reason: "no claim card has that name"}
	}
	if err != nil {
		return claim.Card{}, nil, err
	}
	var c claim.Card
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return claim.Card{}, nil, fmt.Errorf("card %s does not read as one: %w", name, err)
	}
	if err := c.Validate(); err != nil {
		return claim.Card{}, nil, err
	}
	return c, body, nil
}

func claimNames(root string) ([]string, error) {
	des, err := os.ReadDir(claimsDir(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range des {
		if n, ok := strings.CutSuffix(d.Name(), ".json"); ok && claim.ValidName(n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

func addClaimOps(r *ops.Registry, root string) {
	r.Add(ops.Op{Name: "list_claims", CLI: "claim list",
		Summary: "the claim cards registered: each vendor claim's terms, when it was registered, " +
			"and when its window closes",
		Needs: auth.ActView, Area: auth.AreaSecurity, Effect: ops.Read,
		Keywords: []string{"claim", "vendor", "accuracy", "agreement", "renewal", "card"},
		Run: func(c ops.Call) (*answer, error) {
			facts, err := gatherClaims(root)
			if err != nil {
				return nil, err
			}
			return answerClaims(facts, c.Now), nil
		}})
}

// claimFact is one card as list_claims reads it: what the context twin
// records, and what both answer from.
type claimFact struct {
	Name        string    `json:"name"`
	Broken      string    `json:"broken,omitempty"`
	Source      string    `json:"source,omitempty"`
	Metric      string    `json:"metric,omitempty"`
	Direction   string    `json:"direction,omitempty"`
	Threshold   float64   `json:"threshold,omitempty"`
	Confidence  float64   `json:"confidence,omitempty"`
	WindowDays  int       `json:"window_days,omitempty"`
	Registered  int64     `json:"registered,omitempty"`
	WindowStart time.Time `json:"window_start,omitzero"`
	WindowEnd   time.Time `json:"window_end,omitzero"`
}

func gatherClaims(root string) ([]claimFact, error) {
	names, err := claimNames(root)
	if err != nil {
		return nil, err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, err
	}
	out := []claimFact{}
	for _, n := range names {
		card, _, err := loadClaim(root, n)
		if err != nil {
			out = append(out, claimFact{Name: n, Broken: err.Error()})
			continue
		}
		f := claimFact{Name: card.Name, Source: card.Source, Metric: string(card.Metric),
			Direction: string(card.Direction), Threshold: card.Threshold, Confidence: card.Confidence,
			WindowDays: card.WindowDays}
		if reg, err := claim.Registration(events, card); err == nil {
			f.Registered = reg.Seq
			f.WindowStart, f.WindowEnd = card.Window(reg.At)
		} else {
			f.Broken = "its terms match no registration in the audit log"
		}
		out = append(out, f)
	}
	return out, nil
}

func answerClaims(facts []claimFact, now time.Time) *answer {
	rows := ops.List()
	for _, f := range facts {
		row := object().With("name", ours(f.Name))
		if f.Broken != "" && f.Source == "" {
			rows.Add(row.With("broken", ours(f.Broken)))
			continue
		}
		row.With("source", ours(f.Source)).With("metric", ours(f.Metric)).
			With("direction", ours(f.Direction)).With("threshold", ours(f.Threshold)).
			With("confidence", ours(f.Confidence)).With("window_days", ours(f.WindowDays))
		if f.Broken != "" {
			rows.Add(row.With("broken", ours(f.Broken)))
			continue
		}
		rows.Add(row.With("registered_at_entry", ours(int(f.Registered))).
			With("window_start", ours(f.WindowStart)).With("window_end", ours(f.WindowEnd)).
			With("closed", ours(!now.Before(f.WindowEnd))))
	}
	return object().With("claims", rows)
}

func cmdClaim(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("claim needs register, list or test")
	}
	switch args[0] {
	case "register":
		return claimRegister(root, args[1:])
	case "list":
		return runOpCommand(root, provingRegistry(root), "list_claims", args[1:], humanClaims)
	case "test":
		return claimTest(root, args[1:])
	default:
		return fmt.Errorf("unknown claim command %q; try register, list or test", args[0])
	}
}

func claimRegister(root string, args []string) error {
	fs := flag.NewFlagSet("claim register", flag.ContinueOnError)
	source := fs.String("source", "", "the product the claim is about")
	metric := fs.String("metric", "", "agreement, false-closures, escalations-closed, abstentions, "+
		"consistency or adjudicated-false-closures")
	direction := fs.String("direction", "", "at-least or at-most")
	threshold := fs.Float64("threshold", 0, "the rate claimed, between 0 and 1")
	confidence := fs.Float64("confidence", 0.95, "how sure the test must be, at least 0.5")
	windowDays := fs.Int("window-days", 30, "how many days from now the data is counted over")
	labels := fs.String("labels", "people", "for the verdict metrics, where dispositions come from: people or reported")
	minSeverity := fs.String("min-severity", "", "only alerts at least this severe: low, medium, high or critical")
	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("claim register takes NAME and the claim's terms")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	c := claim.Card{Name: name, Nonce: hex.EncodeToString(nonce), Source: *source,
		Metric: claim.Metric(*metric), Threshold: *threshold, Direction: claim.Direction(*direction),
		Confidence: *confidence, WindowDays: *windowDays,
		Population: claim.Population{MinSeverity: *minSeverity}}
	if c.Metric != claim.AdjudicatedFalseClosures {
		switch *labels {
		case "people":
			c.Population.Labels = verdict.People
		case "reported":
			c.Population.Labels = verdict.Reported
		default:
			return fmt.Errorf("--labels is people or reported")
		}
	}
	if err := c.Validate(); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("a claim card is registered by a person")
	}
	if _, err := os.Stat(claimPath(root, name)); err == nil {
		return fmt.Errorf("a card called %s is already registered; a card is never changed, "+
			"because changing its terms after the data arrive is what it exists to prevent", name)
	}
	doc, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(claimsDir(root), 0o700); err != nil {
		return err
	}
	if err := atomicfile.Write(claimPath(root, name), append(doc, '\n'), 0o600); err != nil {
		return err
	}
	if err := recordE(root, caller.auditRecord(claim.RegisteredAction, "/claims/"+name,
		audit.Success, c.RegisterDetail())); err != nil {
		return err
	}
	if w.JSON(map[string]any{"claim": name, "sha256": c.Digest(), "window_days": c.WindowDays}) {
		return nil
	}
	w.Human("card %s registered: only data arriving from now, for %d day(s), counts; "+
		"aertun claim test %s signs the result once the window has closed\n", name, c.WindowDays, name)
	return nil
}

// claimCount is the card's metric over its window, as of now.
func claimCount(root string, c claim.Card, reg adjudicate.Entry, events []audit.Event,
	now time.Time) (proof.Count, error) {
	start, end := c.Window(reg.At)
	until := end
	if now.Before(end) {
		until = now
	}
	if c.Metric == claim.AdjudicatedFalseClosures {
		ids, err := sampleIDs(root)
		if err != nil {
			return proof.Count{}, err
		}
		var drawn []*adjudicate.Sample
		for _, id := range ids {
			s, _, err := loadSample(root, id)
			if err != nil || s.Claim != c.Digest() {
				continue
			}
			drawn = append(drawn, s)
		}
		if len(drawn) != 1 {
			return proof.Count{}, fmt.Errorf("card %s is tested on the one blind sample drawn for it "+
				"(aertun adjudicate draw --claim %s), and %d are", c.Name, c.Name, len(drawn))
		}
		r, err := adjudicate.Verify(drawn[0], events)
		if err != nil {
			return proof.Count{}, err
		}
		if r.Commit.Seq <= reg.Seq {
			return proof.Count{}, fmt.Errorf("the sample for card %s was committed before the card", c.Name)
		}
		return r.AI, nil
	}
	vs, err := loadVerdicts(root, now)
	if err != nil {
		return proof.Count{}, err
	}
	in := verdict.Input{Source: c.Source, Since: start, Until: until, After: reg.At,
		Labels: c.Population.Labels, Verdicts: vs}
	if c.Population.MinSeverity != "" {
		in.MinSeverity = claim.Severities[c.Population.MinSeverity]
	}
	if c.Population.Labels == verdict.People {
		reg, _, err := finding.Load(findingsPath(root))
		if err != nil {
			return proof.Count{}, err
		}
		kept, _ := peoplesVerdicts(events)
		in.Findings, in.Decisions, in.People = reg.All(until), decisionsFrom(events), decisionsFrom(kept)
	}
	n, _ := c.Metric.Of(verdict.Compute(in))
	return n, nil
}

func claimTest(root string, args []string) error {
	fs := flag.NewFlagSet("claim test", flag.ContinueOnError)
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if name == "" || *keyAt == "" {
		return fmt.Errorf("claim test takes NAME --key FILE")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	c, body, err := loadClaim(root, name)
	if err != nil {
		return err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	reg, err := claim.Registration(events, c)
	if err != nil {
		return err
	}
	now := claimNow().UTC()
	n, err := claimCount(root, c, reg, events, now)
	if err != nil {
		return err
	}
	start, end := c.Window(reg.At)
	head := events[len(events)-1]
	st, err := proof.ProveClaim(proof.ClaimInput{Name: c.Name, Card: c.Digest(), Source: c.Source,
		Metric: string(c.Metric), Direction: string(c.Direction), Labels: string(c.Population.Labels),
		MinSeverity: c.Population.MinSeverity, Threshold: c.Threshold, Confidence: c.Confidence,
		Registered:  proof.AuditEntry{Seq: reg.Seq, Hash: reg.Hash, At: reg.At.UTC().Format(time.RFC3339Nano)},
		WindowStart: start, WindowEnd: end, Closed: !now.Before(end), Count: n, CardFile: body,
		Materials: []proof.Material{{Name: "audit-log", Digest: proof.Digest{"sha256": head.Hash},
			Entries: len(events)}},
		Program: version, Now: now})
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
	// Kept only once the window has closed: a proof made while it is open
	// says nothing is decided, and keeping one a day would fill the proving
	// ground with the same nothing.
	if !now.Before(end) {
		if pubDoc, err := json.Marshal(k.PublicKey()); err == nil {
			keepMade(root, env, pubDoc, caller.Name)
		}
	}
	if err := recordE(root, caller.auditRecord("claim.tested", "/claims/"+name, audit.Success,
		map[string]string{"claim": name, "verdict": string(st.Predicate.Verdict),
			"k": fmt.Sprint(n.K), "n": fmt.Sprint(n.N), "closed": fmt.Sprint(!now.Before(end))})); err != nil {
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

func humanClaims(a *answer) string {
	rows := a.Get("claims").Items()
	if len(rows) == 0 {
		return "no claim cards; aertun claim register NAME --source S --metric M --direction D --threshold R registers one"
	}
	var b strings.Builder
	for _, r := range rows {
		if br := r.Get("broken"); br != nil {
			fmt.Fprintf(&b, "%s  %s\n", r.Get("name").Text(), br.Text())
			continue
		}
		state := "window open"
		if r.Get("closed").Value() == true {
			state = "window closed; ready to test"
		}
		fmt.Fprintf(&b, "%s%s%s  %s: %s %s %s, at %s  (%s, closes %s)\n", bold, r.Get("name").Text(), reset,
			r.Get("source").Text(), r.Get("metric").Text(), r.Get("direction").Text(), r.Get("threshold").Text(),
			r.Get("confidence").Text(), state, r.Get("window_end").Text())
	}
	return strings.TrimRight(b.String(), "\n")
}
