// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package ops is the one place an operation is declared, and the three faces
// — the command line, the console and the agent interface — are made from
// the declaration.
//
// # Why one declaration
//
// Each operation used to be written three times: a command, a screen and an
// agent tool, each with its own reading of the arguments, its own call to
// authorise and its own idea of which text came from outside. A table kept by
// hand recorded which surfaces had which operation, and the rules that matter
// most — who may, whether an agent may, what was written down — held only
// where whoever wrote that surface remembered them.
//
// Here an operation says once what it needs, what it changes, what it takes
// and what it answers, and Invoke is the only way to run it. Invoke asks the
// caller's face whether the caller may take that action in that area, refuses
// a change asked for by an agent whatever its grants, writes the record of a
// change before making it, and reads the arguments strictly. A face supplies
// who the caller is and how to ask about them; it cannot skip the asking.
//
// # What an answer carries
//
// An operation answers with an Answer (answer.go), in which every value says
// whether somebody outside this program could have written it. The agent
// interface prints the label beside the value, the console fences the value,
// and the command line prints the label in --json — the same decision, made
// where the value was put in, read by every face.
package ops

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/auth"
)

// Effect is what an operation does to the store.
type Effect string

const (
	// Read changes nothing.
	Read Effect = "read"
	// Propose records something for a person to decide; it decides nothing.
	Propose Effect = "propose"
	// Change changes what is stored. An agent is never let make one.
	Change Effect = "change"
)

// ArgKind is what shape an argument's value takes.
type ArgKind string

const (
	// Text is a line of text.
	Text ArgKind = "text"
	// Number is a whole number.
	Number ArgKind = "number"
	// Flag is true or false.
	Flag ArgKind = "flag"
	// Document is a whole document: a file on the command line, its content
	// on the other faces.
	Document ArgKind = "document"
)

// Bounds on an argument's value, unless the argument declares a smaller one.
const (
	MaxText     = 4096
	MaxDocument = 4 << 20
)

// Arg is one argument an operation takes.
type Arg struct {
	Name     string
	About    string
	Kind     ArgKind
	Required bool
	// Positional says the command line takes it as the operation's one
	// positional argument rather than a flag.
	Positional bool
	// Max is the longest value taken, in bytes; zero is the kind's bound.
	Max int
}

func (a Arg) max() int {
	switch {
	case a.Max > 0:
		return a.Max
	case a.Kind == Document:
		return MaxDocument
	}
	return MaxText
}

// Call is one invocation, as the operation's Run sees it.
type Call struct {
	Caller Caller
	Args   Args
	Now    time.Time
}

// Args are an invocation's arguments, already checked against the
// declaration.
type Args map[string]string

// Text is an argument's value, empty when it was not given.
func (a Args) Text(name string) string { return a[name] }

// Number is a whole-number argument, or def when it was not given.
func (a Args) Number(name string, def int) int {
	if v, ok := a[name]; ok {
		n, _ := strconv.Atoi(v)
		return n
	}
	return def
}

// Flag is a true-or-false argument, false when it was not given.
func (a Args) Flag(name string) bool { return a[name] == "true" }

// Caller is who is asking, as the face they asked through knows them.
type Caller interface {
	// Allowed is nil when the caller may take action in area, and the reason
	// they may not otherwise.
	Allowed(action auth.Action, area string) error
	// Agent reports whether the caller is an AI agent, or acts for one.
	Agent() bool
	// Name is who the caller is, as the store's records name them.
	Name() string
	// Record writes an audit record in the caller's name, and fails when it
	// cannot be written.
	Record(action string, detail map[string]string) error
}

// Op is one operation.
type Op struct {
	// Name is the operation's name on every face: lower case words joined by
	// underscores, a verb last or first as reads naturally.
	Name    string
	Summary string
	Detail  string
	// Needs is the action the caller must hold, in Area.
	Needs auth.Action
	Area  string
	// Effect is what it does to the store; Audit is the record a Propose or
	// a Change writes before it runs.
	Effect Effect
	Audit  string
	Args   []Arg
	// Keywords are what an agent searching for it might say.
	Keywords []string
	// CLI is where it sits on the command line, such as "proof list", when
	// it has a command of its own.
	CLI string
	Run func(Call) (*Answer, error)
}

// Refusal is a decision rather than a malfunction: a face shows it as one,
// and an agent that reads it does not retry.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

// IsRefusal reports whether err is, or wraps, a Refusal.
func IsRefusal(err error) bool {
	var r *Refusal
	return errors.As(err, &r)
}

// ErrUnknown is an operation nobody declared.
var ErrUnknown = errors.New("no operation has that name")

var nameShape = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// Registry holds the operations.
type Registry struct {
	byName map[string]*Op
}

// NewRegistry is an empty registry.
func NewRegistry() *Registry { return &Registry{byName: map[string]*Op{}} }

// Add declares an operation. A declaration that could not be invoked safely
// — no name, no action, no area, a change with no record, nothing to run, an
// argument twice — is a mistake in the program and panics, so it fails the
// first test that builds the registry rather than the first caller.
func (r *Registry) Add(op Op) {
	switch {
	case !nameShape.MatchString(op.Name):
		panic(fmt.Sprintf("ops: %q is not an operation name", op.Name))
	case r.byName[op.Name] != nil:
		panic(fmt.Sprintf("ops: %s is declared twice", op.Name))
	case op.Needs == "" || op.Area == "":
		panic(fmt.Sprintf("ops: %s declares no action or no area to check", op.Name))
	case op.Effect != Read && op.Effect != Propose && op.Effect != Change:
		panic(fmt.Sprintf("ops: %s declares no effect", op.Name))
	case op.Effect != Read && op.Audit == "":
		panic(fmt.Sprintf("ops: %s changes something and declares no record", op.Name))
	case op.Run == nil || strings.TrimSpace(op.Summary) == "":
		panic(fmt.Sprintf("ops: %s has nothing to run or no summary", op.Name))
	}
	seen, positional := map[string]bool{}, 0
	for _, a := range op.Args {
		if !nameShape.MatchString(a.Name) || seen[a.Name] {
			panic(fmt.Sprintf("ops: %s: argument %q is unnamed or named twice", op.Name, a.Name))
		}
		switch a.Kind {
		case Text, Number, Flag, Document:
		default:
			panic(fmt.Sprintf("ops: %s: argument %s has no kind", op.Name, a.Name))
		}
		seen[a.Name] = true
		if a.Positional {
			positional++
		}
	}
	if positional > 1 {
		panic(fmt.Sprintf("ops: %s takes more than one positional argument", op.Name))
	}
	o := op
	r.byName[op.Name] = &o
}

// Get is the operation called name.
func (r *Registry) Get(name string) (Op, bool) {
	o, ok := r.byName[name]
	if !ok {
		return Op{}, false
	}
	return *o, true
}

// Ops are every operation, by name.
func (r *Registry) Ops() []Op {
	out := make([]Op, 0, len(r.byName))
	for _, o := range r.byName {
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Invoke runs the operation called name for c, with the arguments raw, at
// now. It is the only way an operation runs.
func (r *Registry) Invoke(name string, c Caller, raw map[string]string, now time.Time) (*Answer, error) {
	op, ok := r.byName[name]
	if !ok {
		return nil, ErrUnknown
	}
	if c == nil {
		return nil, &Refusal{Reason: "nobody is asking, so nobody can be allowed"}
	}
	// Before the grants: no grant lets an agent make a change, because what
	// an agent decides is a suggestion until a person stands behind it.
	if op.Effect == Change && c.Agent() {
		return nil, &Refusal{Reason: op.Name + " changes what is stored, and an agent " +
			"may propose a change but never make one"}
	}
	if err := c.Allowed(op.Needs, op.Area); err != nil {
		return nil, &Refusal{Reason: err.Error()}
	}
	args, err := op.check(raw)
	if err != nil {
		return nil, err
	}
	if op.Effect != Read {
		// Written first, and the change refused when it cannot be: a change
		// nobody can find a record of is the one this program exists to
		// prevent. The record names the arguments given, never their values,
		// which may be documents or text from outside.
		given := make([]string, 0, len(args))
		for k := range args {
			given = append(given, k)
		}
		sort.Strings(given)
		if err := c.Record(op.Audit, map[string]string{"operation": op.Name,
			"arguments": strings.Join(given, ",")}); err != nil {
			return nil, fmt.Errorf("the record of %s could not be written, so it was not run: %w",
				op.Name, err)
		}
	}
	return op.Run(Call{Caller: c, Args: args, Now: now})
}

// check reads raw against the declaration: an argument the operation does not
// take, one it needs and was not given, one too long, or one not of its kind
// is refused, naming the argument and never echoing its value.
func (op *Op) check(raw map[string]string) (Args, error) {
	decl := map[string]Arg{}
	for _, a := range op.Args {
		decl[a.Name] = a
	}
	out := Args{}
	for k, v := range raw {
		a, ok := decl[k]
		if !ok {
			return nil, &Refusal{Reason: fmt.Sprintf("%s takes no argument called %q", op.Name, clip(k))}
		}
		if len(v) > a.max() {
			return nil, &Refusal{Reason: fmt.Sprintf("%s is longer than the %d bytes %s takes",
				k, a.max(), op.Name)}
		}
		switch a.Kind {
		case Number:
			if _, err := strconv.Atoi(v); err != nil {
				return nil, &Refusal{Reason: k + " is a whole number"}
			}
		case Flag:
			if v != "true" && v != "false" {
				return nil, &Refusal{Reason: k + " is true or false"}
			}
		}
		out[k] = v
	}
	for _, a := range op.Args {
		if a.Required && strings.TrimSpace(out[a.Name]) == "" {
			return nil, &Refusal{Reason: fmt.Sprintf("%s needs %s: %s", op.Name, a.Name, a.About)}
		}
	}
	return out, nil
}

// clip keeps a name that is not an argument's short enough to quote.
func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}
