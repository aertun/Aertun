// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package jcs

import (
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"testing"
)

// The examples below are RFC 8785's own, copied from the published text
// (https://www.rfc-editor.org/rfc/rfc8785.txt) rather than produced by
// this implementation, so the tests hold the code to the specification
// and not to itself.

// Sections 3.2.2 to 3.2.4: the primitive-types sample, its canonical
// form, and the UTF-8 bytes the RFC prints for that form.
func TestRFC8785PrimitiveSampleAndItsBytes(t *testing.T) {
	in := `{
       "numbers": [333333333.33333329, 1E30, 4.50,
                   2e-3, 0.000000000000000000000000001],
       "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
       "literals": [null, true, false]
     }`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,` +
		`1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("canonical form\n got %s\nwant %s", got, want)
	}
	// Section 3.2.4, byte for byte.
	hexBytes := strings.Join(strings.Fields(`
     7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72
     75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a
     5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31
     65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37
     5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30
     30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d`), "")
	wantBytes, err := hex.DecodeString(hexBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wantBytes) {
		t.Fatalf("the bytes differ from section 3.2.4's:\n got %x\nwant %x",
			got, wantBytes)
	}
	// Canonicalising canonical bytes changes nothing.
	again, err := Canonicalize(got)
	if err != nil || string(again) != string(got) {
		t.Fatalf("the canonical form is not a fixed point: %s, %v", again, err)
	}
}

// Section 3.2.3: the sorting test data, whose names span a control
// character, a digit, Latin-1, the BMP above U+E000 and a surrogate pair —
// the case where UTF-8 order and UTF-16 order disagree.
func TestRFC8785SortsNamesByUTF16CodeUnits(t *testing.T) {
	in := `{
       "\u20ac": "Euro Sign",
       "\r": "Carriage Return",
       "\ufb33": "Hebrew Letter Dalet With Dagesh",
       "1": "One",
       "\ud83d\ude00": "Emoji: Grinning Face",
       "\u0080": "Control",
       "\u00f6": "Latin Small Letter O With Diaeresis"
     }`
	want := []string{
		"Carriage Return",
		"One",
		"Control",
		"Latin Small Letter O With Diaeresis",
		"Euro Sign",
		"Emoji: Grinning Face",
		"Hebrew Letter Dalet With Dagesh",
	}
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	at := -1
	for _, v := range want {
		i := strings.Index(string(got), `"`+v+`"`)
		if i < 0 {
			t.Fatalf("%q is missing from %s", v, got)
		}
		if i < at {
			t.Fatalf("%q is out of order in %s; section 3.2.3 sorts by "+
				"UTF-16 code units", v, got)
		}
		at = i
	}
}

// Appendix B: every sample in Table 1, from the IEEE 754 bits to the
// characters, including the two the RFC says must stop a compliant
// implementation.
func TestRFC8785NumberSamples(t *testing.T) {
	for _, c := range []struct {
		bits string
		want string // empty: the RFC's "values out of range", an error
	}{
		{"0000000000000000", "0"},
		{"8000000000000000", "0"},
		{"0000000000000001", "5e-324"},
		{"8000000000000001", "-5e-324"},
		{"7fefffffffffffff", "1.7976931348623157e+308"},
		{"ffefffffffffffff", "-1.7976931348623157e+308"},
		{"4340000000000000", "9007199254740992"},
		{"c340000000000000", "-9007199254740992"},
		{"4430000000000000", "295147905179352830000"},
		{"7fffffffffffffff", ""},
		{"7ff0000000000000", ""},
		{"44b52d02c7e14af5", "9.999999999999997e+22"},
		{"44b52d02c7e14af6", "1e+23"},
		{"44b52d02c7e14af7", "1.0000000000000001e+23"},
		{"444b1ae4d6e2ef4e", "999999999999999700000"},
		{"444b1ae4d6e2ef4f", "999999999999999900000"},
		{"444b1ae4d6e2ef50", "1e+21"},
		{"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
		{"3eb0c6f7a0b5ed8d", "0.000001"},
		{"41b3de4355555553", "333333333.3333332"},
		{"41b3de4355555554", "333333333.33333325"},
		{"41b3de4355555555", "333333333.3333333"},
		{"41b3de4355555556", "333333333.3333334"},
		{"41b3de4355555557", "333333333.33333343"},
		{"becbf647612f3696", "-0.0000033333333333333333"},
		{"43143ff3c1cb0959", "1424953923781206.2"},
	} {
		u, err := strconv.ParseUint(c.bits, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		f := math.Float64frombits(u)
		got, err := FormatNumber(f)
		if c.want == "" {
			// The refusal must be the RFC's, by name, not a formatting
			// accident that happens to fail on these two values today.
			if err == nil || !strings.Contains(err.Error(), "NaN and Infinity") {
				t.Errorf("%s (%v) gave (%q, %v); NaN and Infinity must stop "+
					"a compliant implementation", c.bits, f, got, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s formatted as %q (%v), the RFC says %q", c.bits, got,
				err, c.want)
			continue
		}
		// And through the parser: the RFC's output, read back, writes
		// itself — except the two zeros, which the RFC writes as "0" from
		// two different bit patterns, and that "0" is itself a fixed point.
		back, err := Canonicalize([]byte(c.want))
		if err != nil || string(back) != c.want {
			t.Errorf("%s read back as %q (%v)", c.want, back, err)
		}
	}
}

// The refusals RFC 8785 requires, and the ones a parser that feeds a
// signature owes its reader. Each input is one a lax encoder would have
// quietly turned into some canonical bytes.
func TestCanonicalizeRefusesWhatTheRFCSaysMustStopIt(t *testing.T) {
	for _, c := range []struct {
		name, in, why string
	}{
		{"an escaped lone high surrogate", `"\ud83d"`, "lone surrogate"},
		{"a high surrogate followed by a non-surrogate", `"\ud83d\u0041"`,
			"lone surrogate"},
		{"an escaped lone low surrogate", `"\udead"`, "lone surrogate"},
		{"a surrogate written as UTF-8 bytes", "\"\xed\xba\xad\"",
			"not valid UTF-8"},
		{"invalid UTF-8", "\"\xff\"", "not valid UTF-8"},
		{"a duplicate member", `{"a":1,"a":2}`, "appears twice"},
		{"a duplicate member spelled with an escape", `{"a":1,"\u0061":2}`,
			"appears twice"},
		{"a number beyond the double", `1e400`, "not a finite double"},
		{"a raw control character", "\"a\tb\"", "raw control character"},
		{"two values", `{} {}`, "after the JSON text"},
		{"a leading zero", `01`, "after the JSON text"},
		{"a bare decimal point", `1.`, "no digits after"},
		{"nothing", ``, "ends where a value"},
		{"a comment", `{"a":1 /* hi */}`, "expected ','"},
		{"nesting past the bound", strings.Repeat("[", maxDepth+2) +
			strings.Repeat("]", maxDepth+2), "nesting deeper"},
	} {
		out, err := Canonicalize([]byte(c.in))
		if err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: gave (%q, %v); want a refusal naming %q", c.name,
				out, err, c.why)
		}
	}
	// A number is the nearest double, as JSON.parse reads it: an integer
	// wider than 53 bits lands on its neighbour, which is why a document
	// that signs integers must keep them in range or carry them as
	// strings (the scorecard checks its own round trip for exactly this).
	for in, want := range map[string]string{
		`9007199254740992`:     `9007199254740992`,
		`9007199254740993`:     `9007199254740992`,
		`-9007199254740992`:    `-9007199254740992`,
		`0.1`:                  `0.1`,
		`1E40`:                 `1e+40`,
		`-0`:                   `0`,
		`"\u0000\u001f\u007f"`: `"\u0000\u001f` + "\x7f" + `"`,
	} {
		got, err := Canonicalize([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%s gave (%s, %v), want %s", in, got, err, want)
		}
	}
}

// Marshal is encoding/json then the canonical form: struct field order and
// Go's own escaping do not survive, the RFC's form does.
func TestMarshalCanonicalisesAGoValue(t *testing.T) {
	type doc struct {
		Zed   string  `json:"zed"`
		Alpha float64 `json:"alpha"`
		HTML  string  `json:"html"`
	}
	got, err := Marshal(doc{Zed: "z", Alpha: 4.50, HTML: "<a&b>"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"alpha":4.5,"html":"<a&b>","zed":"z"}`
	if string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if _, err := Marshal(math.NaN()); err == nil {
		t.Fatal("NaN marshalled; it is not a JSON number")
	}
}
