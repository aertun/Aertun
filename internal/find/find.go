// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package find looks for one thing across the console: a screen, or a
// setting, by the words somebody would use for it.
//
// # Why it is not a query language
//
// There is no syntax here — no fields, no operators, no negation, no
// comparison. The input is tokenised into words and the words are looked
// up; a colon, a quote or a bracket is a character in a word and means
// nothing. A query language is the thing that eventually gets an injection.
//
// # Why the kinds are a closed set
//
// Each kind is supplied by the caller, which is what lets the caller apply
// its own access rules before anything is searched rather than filtering
// afterwards.
package find

import (
	"sort"
	"strings"
	"unicode"
)

// Kind is what a hit is. A closed set: a result whose kind the interface
// does not recognise is a row it cannot render.
type Kind string

const (
	// Screen is somewhere in the console. "Where do I set the feeds" is a
	// question the navigation answers only if you already know the group.
	Screen Kind = "screen"
	// Setting is one of the configuration keys, matched on its key and on
	// the summary written for somebody deciding whether to change it.
	Setting Kind = "setting"
)

// A Hit is one thing worth showing, and enough to show it.
type Hit struct {
	Kind Kind `json:"kind"`
	// Title is what to call it.
	Title string `json:"title"`
	// Path is where to go: the screen's route, or the settings screen.
	Path string `json:"path,omitempty"`
	// Why says what matched, so a result is never there by magic.
	Why string `json:"why,omitempty"`
	// Score orders within a kind. Not across them — see Search.
	Score float64 `json:"score"`
}

// Sources is what there is to look through.
//
// Supplied by the caller rather than opened here, so the caller applies its
// own access rules first.
type Sources struct {
	Screens []Destination
	// Settings are the configuration keys this person may see. The caller
	// filters: a viewer has no business finding the token lifetime.
	Settings []Option
}

// Destination is a screen in the interface.
type Destination struct {
	Title string
	Path  string
	// Group is which part of the navigation it sits in, shown so a result
	// teaches where the thing lives rather than only taking you there.
	Group string
	// Also are other words somebody might look for it under. "language" for
	// the translations screen, "password" for access — the vocabulary of the
	// person looking rather than of the person who named the screen.
	Also []string
}

// Option is a configuration key.
type Option struct {
	Key     string
	Summary string
}

// Search returns what matches, best first within each kind: screens, then
// settings, because the most common thing somebody cannot find is a screen,
// and a screen is also the cheapest kind of wrong answer — it costs a click
// and teaches where something lives.
func Search(query string, src Sources, limit int) []Hit {
	terms := tokenise(query)
	if len(terms) == 0 {
		return nil
	}
	if limit <= 0 {
		limit = 20
	}

	var out []Hit
	out = append(out, matchScreens(terms, src.Screens)...)
	out = append(out, matchSettings(terms, src.Settings)...)

	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// maxTerm is the longest word looked up.
const maxTerm = 100

// tokenise splits text into terms: lowercase, split on anything that is
// not a letter or digit, and what is too short or too long dropped.
func tokenise(text string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 1 && len(cur) <= maxTerm {
			out = append(out, string(cur))
		}
		cur = cur[:0]
	}
	for _, r := range text {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			cur = append(cur, unicode.ToLower(r))
		case r == '\'' && len(cur) > 0:
			// An apostrophe inside a word is part of it.
		default:
			flush()
		}
	}
	flush()
	return out
}

// matchScreens scores a destination on its title, group and synonyms.
func matchScreens(terms []string, in []Destination) []Hit {
	var hits []Hit
	for _, d := range in {
		hay := append([]string{d.Title, d.Group, d.Path}, d.Also...)
		n, where := hitsIn(terms, hay)
		if n == 0 {
			continue
		}
		why := "in " + d.Group
		// A match on a synonym is worth saying, because it is the case where
		// the result is not obviously the thing that was asked for.
		if where != "" && !strings.EqualFold(where, d.Title) {
			why += ", matched on " + where
		}
		hits = append(hits, Hit{Kind: Screen, Title: d.Title, Path: d.Path,
			Why: why, Score: float64(n)})
	}
	return ranked(hits)
}

func matchSettings(terms []string, in []Option) []Hit {
	var hits []Hit
	for _, o := range in {
		n, _ := hitsIn(terms, []string{o.Key, o.Summary})
		if n == 0 {
			continue
		}
		hits = append(hits, Hit{Kind: Setting, Title: o.Key, Path: "/settings",
			Why: o.Summary, Score: float64(n)})
	}
	return ranked(hits)
}

// hitsIn counts how many terms match any of the haystacks, and returns the
// haystack that matched first.
//
// A term matches when it begins a word. Not an arbitrary substring, and not a
// whole word either.
//
// # Why not a substring
//
// It was one, and searching "pen" returned the setting network.mode — because
// its summary contains "open". That is the failure the page index avoids by
// matching whole words, and the same failure reaches keys and titles by a
// shorter route: these strings are short, so a spurious match is a large
// fraction of a small result list rather than noise at the bottom of a big one.
//
// # Why not a whole word
//
// Because "lang" has to find Languages and "config" has to find
// config.unset. People type the beginning of a word, and a finder that
// insists on the whole of it is one they stop using after the second time it
// finds nothing.
//
// Words are split on anything that is not a letter or a digit, so a dotted key
// (token.api.ttl.default), a path (/languages) and a phrase all break into the
// same kind of pieces.
func hitsIn(terms []string, hay []string) (int, string) {
	n, first := 0, ""
	for _, t := range terms {
		for _, h := range hay {
			if h == "" || !beginsAWord(h, t) {
				continue
			}
			n++
			if first == "" {
				first = h
			}
			break
		}
	}
	return n, first
}

// beginsAWord reports whether term starts a word in s, case-insensitively.
func beginsAWord(s, term string) bool {
	s = strings.ToLower(s)
	atStart := true
	for i, r := range s {
		if !isWordRune(r) {
			atStart = true
			continue
		}
		if atStart && strings.HasPrefix(s[i:], term) {
			return true
		}
		atStart = false
	}
	return false
}

func isWordRune(r rune) bool {
	return r == '\'' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// ranked sorts by score and then by title, so equal scores come out in the
// same order every time.
//
// Stability matters more than it looks: a list that reorders between two
// identical searches makes somebody think the store changed.
func ranked(hits []Hit) []Hit {
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].Title < hits[j].Title
	})
	return hits
}
