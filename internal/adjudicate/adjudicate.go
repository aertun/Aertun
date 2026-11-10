// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package adjudicate checks closed alerts again, blind, on a random sample
// committed before anybody looks.
//
// # Why
//
// A vendor's AI closing alerts as false positives is only as good as the
// closures that were wrong, and nobody re-opens a closed alert to find out.
// Comparing the AI with the analysts (internal/verdict) measures agreement,
// not truth: where both are wrong in the same way, agreement is perfect. So
// a sample of closures — the AI's and the people's, as two strata — goes
// back to a reviewer who sees the evidence and not who closed it or why,
// and the share judged real is each side's false-closure rate.
//
// # What makes the sample trustworthy
//
// The draw is decided before any review, and written down where it cannot
// be changed afterwards. The seed comes from crypto/rand; which closures it
// selects is a keyed hash of each one (HMAC-SHA256 under the seed), so
// anybody holding the seed and the population can recompute the selection
// without this program; and the seed, a digest of the population and a
// digest of the selected list go into the signed, hash-chained audit log
// before the first item is shown. A proof over the judgements refuses to be
// made unless the judged items are exactly that list, each judged once,
// after the commitment, by a verified person who did not make the original
// closure. A draw nobody liked can be drawn again, and every draw is in the
// log; the proof says how many came before the one it reports.
package adjudicate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"

	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/verdict"
)

// Stratum names the two kinds of closure a sample is drawn from.
const (
	// StratumAI is alerts the vendor's AI answered false-positive or benign.
	StratumAI = "ai"
	// StratumHuman is findings people closed as false-positive or benign.
	StratumHuman = "human"
)

// Population is every closure a sample could have selected, by finding.
//
// Both strata are detection findings, so the two rates are rates over the
// same kind of thing: an alert a rule or a product raised, closed as not
// worth acting on.
type Population struct {
	// AI are findings carrying an alert the AI closed; Human are findings
	// whose last decision by a verified person closed them. Sorted.
	AI    []string `json:"ai"`
	Human []string `json:"human"`
	// Unlinked are AI closures on alerts no single finding carries: there
	// is no evidence here to review them against.
	Unlinked int `json:"unlinked"`
}

// Item is one selected finding, numbered in the order it is reviewed, with
// the strata that selected it. A finding selected by both is reviewed once
// and its judgement counts in both.
type Item struct {
	N       int    `json:"n"`
	Finding string `json:"finding"`
	AI      bool   `json:"ai,omitempty"`
	Human   bool   `json:"human,omitempty"`
}

// Sample is a committed draw.
type Sample struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	// Since and Until bound when the closures were made.
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
	// Claim is the digest of the claim card the sample was drawn for, when
	// it was drawn for one (internal/claim).
	Claim string `json:"claim,omitempty"`
	// Seed is 32 bytes from crypto/rand, in hex.
	Seed       string     `json:"seed"`
	PerStratum int        `json:"per_stratum"`
	Population Population `json:"population"`
	Items      []Item     `json:"items"`
}

// MaxPerStratum bounds a draw: a reviewer judges every item by hand.
const MaxPerStratum = 5000

var (
	sampleID = regexp.MustCompile(`^[0-9a-f]{16}$`)
	hex32    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidID reports whether s is a sample id.
func ValidID(s string) bool { return sampleID.MatchString(s) }

// PopulationInput is what a population is read from.
type PopulationInput struct {
	Source string
	// Since and Until bound when closures were made; After, when set, is a
	// claim's registration, before which nothing counts.
	Since, Until, After time.Time
	Verdicts            []verdict.Verdict
	Findings            []finding.Finding
	// People are the decisions verified people recorded.
	People []finding.Decision
}

// Closures reads the population: the alerts whose standing answer from the
// AI in the period closed them, and the findings whose last decision by a
// verified person in the period closed them.
func Closures(in PopulationInput) Population {
	from := in.Since
	if in.After.After(from) {
		from = in.After
	}
	latest := map[string]verdict.Verdict{}
	for _, v := range in.Verdicts {
		if v.Source != in.Source || v.At.Before(from) || !v.At.Before(in.Until) ||
			!v.Imported.Before(in.Until) ||
			(!in.After.IsZero() && v.Imported.Before(in.After)) {
			continue
		}
		if cur, ok := latest[v.Alert]; !ok || v.At.After(cur.At) ||
			(v.At.Equal(cur.At) && v.Says > cur.Says) {
			latest[v.Alert] = v
		}
	}
	index := verdict.Index(in.Findings)
	var pop Population
	ai := map[string]bool{}
	for key, v := range latest {
		if !v.Says.Closes() {
			continue
		}
		if fs := index[key]; len(fs) == 1 {
			ai[fs[0].ID] = true
		} else {
			pop.Unlinked++
		}
	}
	detection := map[string]bool{}
	for _, f := range in.Findings {
		if f.Kind == finding.FromDetection {
			detection[f.ID] = true
		}
	}
	last := map[string]finding.Decision{}
	for _, d := range in.People {
		if !detection[d.Finding] || !d.At.Before(in.Until) {
			continue
		}
		if cur, ok := last[d.Finding]; !ok || d.At.After(cur.At) ||
			(d.At.Equal(cur.At) && d.To > cur.To) {
			last[d.Finding] = d
		}
	}
	human := map[string]bool{}
	for id, d := range last {
		if verdict.FromState(d.To).Closes() && !d.At.Before(from) {
			human[id] = true
		}
	}
	pop.AI, pop.Human = sortedKeys(ai), sortedKeys(human)
	return pop
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NewSeed reads a seed from r, which is crypto/rand.Reader everywhere but
// a test.
func NewSeed(r io.Reader) (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("no randomness for the seed: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// rank is where a finding falls in one ordering the seed decides.
func rank(seed []byte, label, id string) string {
	m := hmac.New(sha256.New, seed)
	m.Write([]byte(label))
	m.Write([]byte{0})
	m.Write([]byte(id))
	return hex.EncodeToString(m.Sum(nil))
}

// Select is the draw: from each stratum, the per findings that rank lowest
// under the seed, and the union numbered in a third ordering the seed
// decides, so the order items are reviewed in says nothing about which
// stratum selected them.
func Select(pop Population, seedHex string, per int) ([]Item, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		return nil, fmt.Errorf("the seed is not 32 bytes of hex")
	}
	if per < 1 || per > MaxPerStratum {
		return nil, fmt.Errorf("a stratum gives between 1 and %d items", MaxPerStratum)
	}
	chosen := map[string]*Item{}
	pick := func(label string, ids []string, mark func(*Item)) {
		ranked := append([]string(nil), ids...)
		sort.Slice(ranked, func(i, j int) bool {
			return rank(seed, label, ranked[i]) < rank(seed, label, ranked[j])
		})
		for _, id := range ranked[:min(per, len(ranked))] {
			if chosen[id] == nil {
				chosen[id] = &Item{Finding: id}
			}
			mark(chosen[id])
		}
	}
	pick(StratumAI, pop.AI, func(it *Item) { it.AI = true })
	pick(StratumHuman, pop.Human, func(it *Item) { it.Human = true })
	items := make([]Item, 0, len(chosen))
	for _, it := range chosen {
		items = append(items, *it)
	}
	sort.Slice(items, func(i, j int) bool {
		return rank(seed, "order", items[i].Finding) < rank(seed, "order", items[j].Finding)
	})
	for i := range items {
		items[i].N = i + 1
	}
	return items, nil
}

// Draw makes a sample from a population and a seed.
func Draw(source string, since, until time.Time, claim string, pop Population,
	seed string, per int) (*Sample, error) {

	if !verdict.ValidSource(source) {
		return nil, fmt.Errorf("the source is not a short lower-case name")
	}
	items, err := Select(pop, seed, per)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("nothing was closed as false-positive or benign in the period, " +
			"by the AI or by people, so there is nothing to sample")
	}
	s := &Sample{Source: source, Since: since.UTC(), Until: until.UTC(), Claim: claim,
		Seed: seed, PerStratum: per, Population: pop, Items: items}
	sum := sha256.Sum256([]byte(seed + s.SelectionDigest()))
	s.ID = hex.EncodeToString(sum[:])[:16]
	return s, nil
}

func digest(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Marshalling these plain structs cannot fail; a digest of nothing
		// would match nothing, which is the safe answer if it ever did.
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SelectionDigest is the sha256 of the selected list, the commitment's
// subject.
func (s *Sample) SelectionDigest() string { return digest(s.Items) }

// PopulationDigest is the sha256 of the population it was drawn from.
func (s *Sample) PopulationDigest() string { return digest(s.Population) }

// Check refuses a sample whose selection is not what its seed and
// population decide, so an edited sample file is caught before its digest
// is even compared with the log's.
func (s *Sample) Check() error {
	if !ValidID(s.ID) || !hex32.MatchString(s.Seed) || !verdict.ValidSource(s.Source) {
		return fmt.Errorf("the sample's id, seed or source is not in its shape")
	}
	if s.Claim != "" && !hex32.MatchString(s.Claim) {
		return fmt.Errorf("the sample's claim is not a digest")
	}
	want, err := Select(s.Population, s.Seed, s.PerStratum)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(s.Items)
	if string(a) != string(b) {
		return fmt.Errorf("sample %s lists items its seed and population do not select", s.ID)
	}
	sum := sha256.Sum256([]byte(s.Seed + s.SelectionDigest()))
	if hex.EncodeToString(sum[:])[:16] != s.ID {
		return fmt.Errorf("sample %s is not the id of its own selection", s.ID)
	}
	return nil
}

// Item returns the n-th item.
func (s *Sample) Item(n int) (Item, bool) {
	if n < 1 || n > len(s.Items) {
		return Item{}, false
	}
	return s.Items[n-1], true
}

// Counts are how many items each stratum gave.
func (s *Sample) Counts() (ai, human int) {
	for _, it := range s.Items {
		if it.AI {
			ai++
		}
		if it.Human {
			human++
		}
	}
	return ai, human
}

// Closers are the principals, as the log records them, who closed a
// finding as false-positive or benign at any time: none of them may review
// it, because none of them would be looking at it for the first time.
func Closers(id string, decisions []finding.Decision) map[string]bool {
	out := map[string]bool{}
	for _, d := range decisions {
		if d.Finding == id && verdict.FromState(d.To).Closes() {
			out[d.By] = true
		}
	}
	return out
}
