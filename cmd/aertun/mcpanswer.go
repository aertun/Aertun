// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"
)

// An answer is what one read operation on the agent interface says, built
// once and printed two ways.
//
// The agent interface prints the values, as it always has. The context twin
// (mcptwin.go) prints each value beside whether an attacker could have
// written it. Both prints walk the same answer, built by the operation's
// own code, so the twin cannot say anything the agent interface would not
// have said, and a label cannot disagree with how the agent interface
// treated the value it labels: a value is attacker-writable by being built
// with outside, and outside is what fences it. There is one decision per
// value, made where the value is put into the answer, and both surfaces
// read that one decision.
//
// The line between the two is the one the evidence fence and the analyst
// already draw (internal/analyst's Facts and Untrusted). Text that came
// from outside this program is outside: an event's words, the entity a log
// named, a feed's or an inventory's identifiers, a title or a sentence
// built around any of those, and the summary an automation declared an
// incident with. A count, a time, a ratio or a word from a closed set the
// program defines is ours, even when it was counted from the log, because
// it carries no words anybody chose; so is text the people who run this
// program wrote, such as a rule's name, a decision's reason or a regime.
// When a value could be either, it is outside: a label that says an
// attacker could have written something they could not costs a reader a
// second look, and the other mistake costs them the investigation.
type answer struct {
	leaf    bool
	value   any
	outside bool

	list bool
	// absent is a list or an object that is not there at all, which the
	// agent interface has always printed as null — encoding/json's word for
	// a nil slice or map — and the twin prints as an empty container, since
	// it holds no value to label.
	absent bool
	keys   []string
	items  []*answer
}

// ours is a value this program worked out, a word from a closed set it
// defines, or text written by the people who run it.
func ours(v any) *answer { return &answer{leaf: true, value: v} }

// outside is text an attacker could have written. It is fenced on the way
// in — cleaned of what draws nothing, kept to one line, unable to close a
// fence, bounded — exactly as evidence text always was, so the value the
// agent interface prints and the value the twin labels are the same
// fenced text.
func outside(s string) *answer { return &answer{leaf: true, value: fenced(s), outside: true} }

// object starts an object whose keys print in the order they are added.
func object() *answer { return &answer{} }

// with adds one key to an object.
func (a *answer) with(key string, v *answer) *answer {
	a.keys = append(a.keys, key)
	a.items = append(a.items, v)
	return a
}

// listOf is a list of answers, one per item; a nil slice is an absent
// list, as encoding/json prints it.
func listOf[T any](in []T, each func(T) *answer) *answer {
	l := &answer{list: true, absent: in == nil}
	for _, x := range in {
		l.items = append(l.items, each(x))
	}
	return l
}

// oursText is ours for a string, shaped for listOf.
func oursText(s string) *answer { return ours(s) }

// byKey is an object with one key per map entry, in sorted order, as
// encoding/json prints a map; a nil map is an absent object.
func byKey[K ~string, V any](m map[K]V, each func(V) *answer) *answer {
	o := &answer{absent: m == nil}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	for _, k := range keys {
		o.with(k, each(m[K(k)]))
	}
	return o
}

// plain is the answer as the agent interface prints it: compact JSON of
// the values, byte for byte what encoding/json printed for the same values
// in the same order.
func (a *answer) plain() (string, error) {
	var b bytes.Buffer
	if err := a.print(&b, false); err != nil {
		return "", err
	}
	return b.String(), nil
}

// labelled is the answer as the context twin prints it: every value as
// {"value": …, "attacker_writable": true|false}.
func (a *answer) labelled() (string, error) {
	var b bytes.Buffer
	if err := a.print(&b, true); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (a *answer) print(b *bytes.Buffer, labels bool) error {
	switch {
	case a.leaf:
		// One value per label. A list or an object carried as one value
		// would put several things under one label, and the label would
		// be true of some of them at most; those are built as lists and
		// objects of values instead, and anything else is refused here
		// rather than printed under a label it might not deserve.
		switch a.value.(type) {
		case string, bool, int, float64, time.Time:
		default:
			return fmt.Errorf("an answer holds a %T as one value; a value is "+
				"one string, number, truth or time, so that one label is true "+
				"of all of it", a.value)
		}
		v, err := json.Marshal(a.value)
		if err != nil {
			return err
		}
		if !labels {
			b.Write(v)
			return nil
		}
		b.WriteString(`{"value":`)
		b.Write(v)
		b.WriteString(`,"attacker_writable":`)
		b.WriteString(strconv.FormatBool(a.outside))
		b.WriteByte('}')
		return nil
	case a.list:
		if a.absent && !labels {
			b.WriteString("null")
			return nil
		}
		b.WriteByte('[')
		for i, item := range a.items {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := item.print(b, labels); err != nil {
				return err
			}
		}
		b.WriteByte(']')
		return nil
	}
	if a.absent && !labels {
		b.WriteString("null")
		return nil
	}
	b.WriteByte('{')
	for i, k := range a.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := json.Marshal(k)
		if err != nil {
			return err
		}
		b.Write(key)
		b.WriteByte(':')
		if err := a.items[i].print(b, labels); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}
