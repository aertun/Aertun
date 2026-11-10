// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package verdict

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Reading a vendor's export.
//
// Two shapes, both strict. JSON lines, one verdict per line, with exactly
// these fields; or CSV with a header naming exactly these columns:
//
//	alert           the alert's key in the product (required)
//	verdict         real, false-positive, benign, escalate or abstain (required)
//	at              when it was given, RFC 3339 (required)
//	confidence      between 0 and 1
//	disposition     what the product says a person decided: real,
//	                false-positive or benign
//	disposition_at  when the person decided, RFC 3339 (required with a
//	                disposition)
//	source          the product's short name; when present it must be the
//	                one the import was given
//
// A field or column outside the list is refused, not skipped: an export
// carrying a title, a description or the model's reasoning is carrying text
// somebody else wrote, and the import would rather be handed a file without
// it than decide which of it to keep. The error names the line and never
// echoes what was on it, because what was on it is that text.

// Format is the shape of an export.
type Format string

const (
	JSONLines Format = "jsonl"
	CSV       Format = "csv"
)

const (
	// MaxImport bounds one file. An export of verdicts is a few hundred
	// bytes a row; this is generous and finite.
	MaxImport = 64 << 20
	// MaxRows bounds the rows one import takes.
	MaxRows = 500_000
	// MaxLine bounds one row. A verdict with only the fields above is far
	// shorter; anything longer is carrying something else.
	MaxLine = 4096
)

// Columns are the fields an export may carry, in the order a header names
// them most often.
var Columns = []string{"alert", "verdict", "at", "confidence", "disposition", "disposition_at", "source"}

// row is one line of a JSON-lines export, as written.
type row struct {
	Alert         string   `json:"alert"`
	Verdict       string   `json:"verdict"`
	At            string   `json:"at"`
	Confidence    *float64 `json:"confidence"`
	Disposition   string   `json:"disposition"`
	DispositionAt string   `json:"disposition_at"`
	Source        string   `json:"source"`
}

// Parse reads an export of source's verdicts, refusing the whole file at
// the first row that is not one. Every verdict is stamped Imported at now.
func Parse(r io.Reader, format Format, source string, now time.Time) ([]Verdict, error) {
	if !ValidSource(source) {
		return nil, fmt.Errorf("the source is not a short lower-case name (2 to 32 of a-z, 0-9 and -)")
	}
	body, err := io.ReadAll(io.LimitReader(r, MaxImport+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxImport {
		return nil, fmt.Errorf("the file is larger than the %d bytes one import takes", MaxImport)
	}
	var rows []row
	switch format {
	case JSONLines:
		rows, err = jsonRows(body)
	case CSV:
		rows, err = csvRows(body)
	default:
		return nil, fmt.Errorf("the format is jsonl or csv")
	}
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("the file holds no verdicts")
	}
	out := make([]Verdict, 0, len(rows))
	for i, rw := range rows {
		v, err := rw.verdict(source, now)
		if err != nil {
			return nil, fmt.Errorf("row %d: %w", i+1, err)
		}
		out = append(out, v)
	}
	return out, nil
}

func jsonRows(body []byte) ([]row, error) {
	var rows []row
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, MaxLine), MaxLine)
	for line := 1; sc.Scan(); line++ {
		text := bytes.TrimSpace(sc.Bytes())
		if len(text) == 0 {
			continue
		}
		if len(rows) == MaxRows {
			return nil, fmt.Errorf("the file holds more than the %d rows one import takes", MaxRows)
		}
		var rw row
		dec := json.NewDecoder(bytes.NewReader(text))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rw); err != nil {
			return nil, fmt.Errorf("line %d is not a verdict with only the fields %s",
				line, strings.Join(Columns, ", "))
		}
		if dec.More() {
			return nil, fmt.Errorf("line %d holds more than one verdict", line)
		}
		rows = append(rows, rw)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("a line is longer than the %d bytes a verdict needs", MaxLine)
		}
		return nil, err
	}
	return rows, nil
}

func csvRows(body []byte) ([]row, error) {
	cr := csv.NewReader(bytes.NewReader(body))
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("the file has no header row naming its columns")
	}
	at := map[string]int{}
	for i, h := range header {
		h = strings.TrimSpace(strings.TrimPrefix(h, "\ufeff"))
		known := false
		for _, c := range Columns {
			known = known || c == h
		}
		if !known {
			return nil, fmt.Errorf("column %d is not one this import reads (only %s)",
				i+1, strings.Join(Columns, ", "))
		}
		if _, twice := at[h]; twice {
			return nil, fmt.Errorf("the header names %s twice", h)
		}
		at[h] = i
	}
	for _, need := range []string{"alert", "verdict", "at"} {
		if _, ok := at[need]; !ok {
			return nil, fmt.Errorf("the header has no %s column", need)
		}
	}
	cr.FieldsPerRecord = len(header)
	var rows []row
	for line := 2; ; line++ {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("line %d is not a CSV row with %d fields", line, len(header))
		}
		if len(rows) == MaxRows {
			return nil, fmt.Errorf("the file holds more than the %d rows one import takes", MaxRows)
		}
		get := func(name string) string {
			if i, ok := at[name]; ok {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		for _, f := range rec {
			if len(f) > MaxLine {
				return nil, fmt.Errorf("line %d has a field longer than a verdict needs", line)
			}
		}
		rw := row{Alert: get("alert"), Verdict: get("verdict"), At: get("at"),
			Disposition: get("disposition"), DispositionAt: get("disposition_at"),
			Source: get("source")}
		if c := get("confidence"); c != "" {
			f, perr := strconv.ParseFloat(c, 64)
			if perr != nil {
				return nil, fmt.Errorf("line %d: the confidence is not a number", line)
			}
			rw.Confidence = &f
		}
		rows = append(rows, rw)
	}
	return rows, nil
}

// verdict turns a row into a verdict, checked.
func (rw row) verdict(source string, now time.Time) (Verdict, error) {
	if rw.Source != "" && rw.Source != source {
		return Verdict{}, fmt.Errorf("the row names a different source from the one being imported")
	}
	v := Verdict{Source: source, Alert: rw.Alert, Says: Word(rw.Verdict),
		Confidence: rw.Confidence, Reported: Word(rw.Disposition), Imported: now.UTC()}
	at, err := time.Parse(time.RFC3339Nano, rw.At)
	if err != nil {
		return Verdict{}, fmt.Errorf("the time is not RFC 3339")
	}
	v.At = at.UTC()
	if rw.DispositionAt != "" {
		dat, err := time.Parse(time.RFC3339Nano, rw.DispositionAt)
		if err != nil {
			return Verdict{}, fmt.Errorf("the disposition time is not RFC 3339")
		}
		v.ReportedAt = dat.UTC()
	}
	if err := v.Validate(now); err != nil {
		return Verdict{}, err
	}
	return v, nil
}
