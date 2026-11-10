// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package ops

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"
)

// An Answer is what one operation says, built once and shown by every face.
//
// The agent interface prints the values; the context twin prints each value
// beside whether an attacker could have written it; the console fences the
// values that came from outside. All of them walk the same answer, built by
// the operation's own code, so no face can say anything another would not,
// and a label cannot disagree with how a face treated the value it labels: a
// value is attacker-writable by being built with Outside, and Outside is what
// fences it. There is one decision per value, made where the value is put
// into the answer, and every face reads that one decision.
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
type Answer struct {
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
	items  []*Answer
}

// Ours is a value this program worked out, a word from a closed set it
// defines, or text written by the people who run it.
func Ours(v any) *Answer { return &Answer{leaf: true, value: v} }

// Outside is text an attacker could have written. It is fenced on the way
// in — cleaned of what draws nothing, kept to one line, unable to close a
// fence, bounded — exactly as evidence text always was, so the value the
// agent interface prints and the value the twin labels are the same
// fenced text.
func Outside(s string) *Answer { return &Answer{leaf: true, value: Fence(s), outside: true} }

// List is a list that is there, with nothing in it yet: printed as [] when
// empty, never as null.
func List() *Answer { return &Answer{list: true} }

// Absent marks a list or an object as not there at all when gone is true:
// printed as null by Plain, as encoding/json prints a nil slice, and as an
// empty container by Labelled, which has no value to label.
func (a *Answer) Absent(gone bool) *Answer {
	a.absent = gone
	return a
}

// Add appends item to a list.
func (a *Answer) Add(item *Answer) *Answer {
	a.items = append(a.items, item)
	return a
}

// Object starts an object whose keys print in the order they are added.
func Object() *Answer { return &Answer{} }

// With adds one key to an object.
func (a *Answer) With(key string, v *Answer) *Answer {
	a.keys = append(a.keys, key)
	a.items = append(a.items, v)
	return a
}

// ListOf is a list of answers, one per item; a nil slice is an absent
// list, as encoding/json prints it.
func ListOf[T any](in []T, each func(T) *Answer) *Answer {
	l := &Answer{list: true, absent: in == nil}
	for _, x := range in {
		l.items = append(l.items, each(x))
	}
	return l
}

// OursText is Ours for a string, shaped for ListOf.
func OursText(s string) *Answer { return Ours(s) }

// ByKey is an object with one key per map entry, in sorted order, as
// encoding/json prints a map; a nil map is an absent object.
func ByKey[K ~string, V any](m map[K]V, each func(V) *Answer) *Answer {
	o := &Answer{absent: m == nil}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	for _, k := range keys {
		o.With(k, each(m[K(k)]))
	}
	return o
}

// Plain is the answer as the agent interface prints it: compact JSON of
// the values, byte for byte what encoding/json printed for the same values
// in the same order.
func (a *Answer) Plain() (string, error) {
	var b bytes.Buffer
	if err := a.print(&b, false); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Labelled is the answer as the context twin prints it: every value as
// {"value": …, "attacker_writable": true|false}.
func (a *Answer) Labelled() (string, error) {
	var b bytes.Buffer
	if err := a.print(&b, true); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (a *Answer) print(b *bytes.Buffer, labels bool) error {
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

// The accessors are for a face that lays an answer out itself, as the
// console does, rather than printing it whole.

// Leaf reports whether a is one value.
func (a *Answer) Leaf() bool { return a != nil && a.leaf }

// Value is a leaf's value, nil for anything else.
func (a *Answer) Value() any {
	if !a.Leaf() {
		return nil
	}
	return a.value
}

// Text is a leaf's value as a person reads it: a string as it is, anything
// else formatted.
func (a *Answer) Text() string {
	switch v := a.Value().(type) {
	case nil:
		return ""
	case string:
		return v
	case time.Time:
		return v.UTC().Format(time.RFC3339)
	default:
		return fmt.Sprint(v)
	}
}

// IsOutside reports whether a is a value somebody outside this program could
// have written.
func (a *Answer) IsOutside() bool { return a.Leaf() && a.outside }

// Get is an object's value under key, nil when it has none.
func (a *Answer) Get(key string) *Answer {
	if a == nil || a.leaf || a.list {
		return nil
	}
	for i, k := range a.keys {
		if k == key {
			return a.items[i]
		}
	}
	return nil
}

// Keys are an object's keys, in the order they were added; nil for anything
// else.
func (a *Answer) Keys() []string {
	if a == nil || a.leaf || a.list {
		return nil
	}
	return append([]string(nil), a.keys...)
}

// Items are a list's members, nil for anything else.
func (a *Answer) Items() []*Answer {
	if a == nil || !a.list {
		return nil
	}
	return a.items
}
