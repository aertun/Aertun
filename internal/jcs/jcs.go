// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package jcs is the JSON Canonicalization Scheme of RFC 8785: one JSON
// text in, the one byte sequence every conforming implementation produces
// for it out.
//
// # Why a signed document needs it
//
// A digest or a signature covers bytes, and JSON lets the same data be
// written many ways: members in any order, insignificant whitespace,
// "4.50" and "4.5", "A" and "A". A document whose signed bytes are
// whatever one encoder happened to emit can only be verified by that
// encoder, in that version, with that struct declaration — so a verifier
// written in another language, or this program after a field moves, could
// not check it. RFC 8785 fixes the form: members sorted by their names as
// UTF-16 code units, no whitespace, strings escaped by one rule, and
// numbers written the way ECMAScript writes them. A third party with any
// conforming canonicaliser recomputes the same bytes from the same data.
//
// # What this implementation refuses
//
// RFC 8785 section 3.1 requires I-JSON input, and its section 3.2.2 says
// what a compliant implementation must refuse; each refusal here is one of
// those, and fails closed rather than producing bytes a signature would
// then cover:
//
//   - a lone surrogate, escaped or as bytes (section 3.2.2.2);
//   - a number that is not finite as a double (section 3.2.2.3);
//   - an object with two members of the same name (section 3.1).
//
// A number is read as the nearest double, as JSON.parse reads it, and
// written as that double: "9007199254740993" canonicalises to
// 9007199254740992, which is what section 3.1 means by number data that
// must be expressible as a double. That is the specification, and the
// Appendix B samples depend on it (295147905179352830000 is how
// ECMAScript writes 2^68), so it is not refused here. A caller whose
// document could carry an integer wider than 53 bits must carry it as a
// string, or check that its canonical bytes decode back to the value it
// meant — which is what the wind tunnel's scorecard does before it seals.
//
// Anything that is not JSON at all — a trailing token, a control character
// inside a string, invalid UTF-8, nesting deeper than maxDepth — is refused
// as well, because a canonical form of something unparseable is a form of
// a guess.
//
// The parser is written here rather than borrowed from encoding/json
// because encoding/json replaces a lone surrogate and invalid UTF-8 with
// U+FFFD without saying so and keeps the last of two duplicate members,
// and each of those is a refusal above.
package jcs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// maxDepth bounds nesting, so a hostile document of ten thousand opening
// brackets is refused instead of exhausting the stack that parses it.
const maxDepth = 512

// Canonicalize returns the RFC 8785 canonical form of one JSON text.
func Canonicalize(in []byte) ([]byte, error) {
	p := &parser{s: in}
	p.space()
	out, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("jcs: unexpected %q after the JSON text at "+
			"byte %d; one document is one value", p.s[p.i], p.i)
	}
	return out, nil
}

// Marshal encodes v with encoding/json and returns the canonical form of
// the result — the bytes a digest or a signature over v should cover.
func Marshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonicalize(raw)
}

type parser struct {
	s []byte
	i int
}

// space skips the four whitespace bytes JSON allows between tokens. None
// of them survives into the canonical form (RFC 8785 section 3.2.1).
func (p *parser) space() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("jcs: nesting deeper than %d", maxDepth)
	}
	if p.i >= len(p.s) {
		return nil, fmt.Errorf("jcs: the JSON text ends where a value " +
			"was expected")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return appendString(nil, s), nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	for _, lit := range []string{"true", "false", "null"} {
		if bytes.HasPrefix(p.s[p.i:], []byte(lit)) {
			p.i += len(lit)
			return []byte(lit), nil
		}
	}
	return nil, fmt.Errorf("jcs: %q at byte %d does not begin a JSON "+
		"value", p.s[p.i], p.i)
}

type member struct {
	name  string
	units []uint16
	value []byte
}

func (p *parser) object(depth int) ([]byte, error) {
	p.i++ // {
	var members []member
	seen := map[string]bool{}
	p.space()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return []byte("{}"), nil
	}
	for {
		p.space()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, fmt.Errorf("jcs: an object member name must be a "+
				"string, at byte %d", p.i)
		}
		name, err := p.str()
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, fmt.Errorf("jcs: the member %q appears twice in one "+
				"object; RFC 8785 section 3.1 forbids it, and which of the "+
				"two a reader keeps is the reader's guess", name)
		}
		seen[name] = true
		p.space()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, fmt.Errorf("jcs: expected ':' after the member name "+
				"%q", name)
		}
		p.i++
		p.space()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		members = append(members, member{name: name,
			units: utf16.Encode([]rune(name)), value: v})
		p.space()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("jcs: the object never closes")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == '}' {
			p.i++
			break
		}
		return nil, fmt.Errorf("jcs: expected ',' or '}' at byte %d", p.i)
	}
	// Section 3.2.3: names compared as arrays of UTF-16 code units, as
	// unsigned integers, independent of locale. Go strings are UTF-8, and
	// UTF-8 order differs from UTF-16 order above U+FFFF against
	// U+E000..U+FFFF, so the comparison is made on the converted units.
	sort.Slice(members, func(a, b int) bool {
		return lessUnits(members[a].units, members[b].units)
	})
	out := []byte{'{'}
	for i, m := range members {
		if i > 0 {
			out = append(out, ',')
		}
		out = appendString(out, m.name)
		out = append(out, ':')
		out = append(out, m.value...)
	}
	return append(out, '}'), nil
}

// lessUnits is the section 3.2.3 order: the first differing code unit
// decides, and a proper prefix sorts first.
func lessUnits(a, b []uint16) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func (p *parser) array(depth int) ([]byte, error) {
	p.i++ // [
	out := []byte{'['}
	p.space()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return []byte("[]"), nil
	}
	for n := 0; ; n++ {
		p.space()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			out = append(out, ',')
		}
		out = append(out, v...)
		p.space()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("jcs: the array never closes")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == ']' {
			p.i++
			return append(out, ']'), nil
		}
		return nil, fmt.Errorf("jcs: expected ',' or ']' at byte %d", p.i)
	}
}

// str parses one string token into the code points it denotes, refusing
// what RFC 8259 does not allow in a string and what RFC 8785 section
// 3.2.2.2 says must stop a compliant implementation: a lone surrogate.
func (p *parser) str() (string, error) {
	start := p.i
	p.i++ // "
	var b strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", fmt.Errorf("jcs: the string at byte %d never closes",
				start)
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c == '\\':
			r, err := p.escape()
			if err != nil {
				return "", err
			}
			b.WriteRune(r)
		case c < 0x20:
			return "", fmt.Errorf("jcs: a raw control character (0x%02x) "+
				"inside the string at byte %d; JSON requires it escaped",
				c, start)
		default:
			r, size := utf8.DecodeRune(p.s[p.i:])
			if r == utf8.RuneError && size <= 1 {
				// Go's decoder reports the UTF-8 encoding of a surrogate
				// (ED A0 80 and kin) as invalid too, so a lone surrogate
				// written as bytes is refused here with the rest.
				return "", fmt.Errorf("jcs: the string at byte %d is not "+
					"valid UTF-8, so it is not expressible as Unicode "+
					"(RFC 8785 section 3.1)", start)
			}
			b.WriteRune(r)
			p.i += size
		}
	}
}

// escape reads one backslash escape, pairing a high surrogate with the low
// surrogate that must follow it.
func (p *parser) escape() (rune, error) {
	if p.i+1 >= len(p.s) {
		return 0, fmt.Errorf("jcs: a backslash ends the text")
	}
	c := p.s[p.i+1]
	p.i += 2
	switch c {
	case '"':
		return '"', nil
	case '\\':
		return '\\', nil
	case '/':
		return '/', nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
	default:
		return 0, fmt.Errorf("jcs: \\%c is not a JSON escape", c)
	}
	hi, err := p.hex4()
	if err != nil {
		return 0, err
	}
	switch {
	case utf16.IsSurrogate(rune(hi)) && hi < 0xDC00:
		// A high surrogate: the next six bytes must be \u and a low one.
		if p.i+1 < len(p.s) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
			p.i += 2
			lo, err := p.hex4()
			if err != nil {
				return 0, err
			}
			if lo >= 0xDC00 && lo <= 0xDFFF {
				return utf16.DecodeRune(rune(hi), rune(lo)), nil
			}
		}
		return 0, fmt.Errorf("jcs: the high surrogate \\u%04x is not "+
			"followed by a low one; RFC 8785 section 3.2.2.2 requires a "+
			"compliant implementation to stop on a lone surrogate", hi)
	case utf16.IsSurrogate(rune(hi)):
		return 0, fmt.Errorf("jcs: the low surrogate \\u%04x has no high "+
			"surrogate before it; RFC 8785 section 3.2.2.2 requires a "+
			"compliant implementation to stop on a lone surrogate", hi)
	}
	return rune(hi), nil
}

func (p *parser) hex4() (uint16, error) {
	if p.i+4 > len(p.s) {
		return 0, fmt.Errorf("jcs: a \\u escape needs four hex digits")
	}
	v, err := strconv.ParseUint(string(p.s[p.i:p.i+4]), 16, 16)
	if err != nil {
		return 0, fmt.Errorf("jcs: %q is not four hex digits",
			p.s[p.i:p.i+4])
	}
	p.i += 4
	return uint16(v), nil
}

// number reads one number token by RFC 8259's grammar — a strict one: no
// leading zeros, no leading plus, no bare decimal point — and writes the
// double it denotes the way ECMAScript writes it.
func (p *parser) number() ([]byte, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	digits := func() int {
		n := 0
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	switch {
	case p.i < len(p.s) && p.s[p.i] == '0':
		p.i++
	case digits() == 0:
		return nil, fmt.Errorf("jcs: a number at byte %d has no digits",
			start)
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		if digits() == 0 {
			return nil, fmt.Errorf("jcs: a number at byte %d has no digits "+
				"after its decimal point", start)
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			return nil, fmt.Errorf("jcs: a number at byte %d has no digits "+
				"in its exponent", start)
		}
	}
	lit := string(p.s[start:p.i])
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return nil, fmt.Errorf("jcs: %s is not a finite double; RFC 8785 "+
			"section 3.2.2.3 requires a compliant implementation to stop "+
			"on one", lit)
	}
	s, err := FormatNumber(f)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// FormatNumber writes a double the way ECMAScript's Number::toString does
// (ECMA-262 section 7.1.12.1, with its Note 2), which is what RFC 8785
// section 3.2.2.3 requires: the shortest digit string that reads back as
// the same double, laid out in plain notation for decimal exponents from
// -6 through 20 and in exponent notation outside them.
//
// strconv's shortest formatting supplies the digits; this function only
// lays them out, so the digit choice is the standard library's, which the
// RFC's Appendix B samples hold it to in the tests.
func FormatNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("jcs: %v is not a JSON number; RFC 8785 "+
			"section 3.2.2.3 requires a compliant implementation to stop "+
			"on NaN and Infinity", f)
	}
	if f == 0 {
		// Minus zero included: ECMAScript writes both as 0.
		return "0", nil
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d[.ddd]e±XX
	mant, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, err := strconv.Atoi(exp)
	if err != nil {
		return "", fmt.Errorf("jcs: formatting %v: %w", f, err)
	}
	// ECMA-262's names: k digits, and n such that the value is
	// 0.digits × 10^n.
	k, n := len(digits), x+1
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		esign := "+"
		if n-1 < 0 {
			esign = "-"
		}
		abs := n - 1
		if abs < 0 {
			abs = -abs
		}
		lead := digits[:1]
		if k > 1 {
			lead += "." + digits[1:]
		}
		out = lead + "e" + esign + strconv.Itoa(abs)
	}
	return sign + out, nil
}

// appendString writes a string by RFC 8785 section 3.2.2.2: the two
// characters JSON must escape as \" and \\, the five control characters
// with short forms as \b \t \n \f \r, the other controls below U+0020 as
// lowercase \u00hh, and everything else as itself.
func appendString(out []byte, s string) []byte {
	out = append(out, '"')
	for _, r := range s {
		switch r {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '\b':
			out = append(out, '\\', 'b')
		case '\t':
			out = append(out, '\\', 't')
		case '\n':
			out = append(out, '\\', 'n')
		case '\f':
			out = append(out, '\\', 'f')
		case '\r':
			out = append(out, '\\', 'r')
		default:
			if r < 0x20 {
				out = append(out, fmt.Sprintf(`\u%04x`, r)...)
				continue
			}
			out = utf8.AppendRune(out, r)
		}
	}
	return append(out, '"')
}
