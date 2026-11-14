// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"fmt"
	"sort"
	"strings"
)

// The technique heatmap: the coverage grid every breach-and-attack
// product renders, in the aertun tradition — categorical words from
// twin-scored scenarios, never a vendor percentage, and never a colour a
// reader has to perceive.
//
// # The accessibility decision, made here and stated on the render
//
// The research asked for a colour-blind-safe ramp with the count printed
// in every cell, and for the one case where the palette cannot promise
// redundancy: the text grid alone. A terminal is exactly that case. This
// program's writer colours its output only when stdout is a terminal, and
// it has no way to know which of the sixteen colours it asks for arrive
// on the other end — a reader's theme, a monochrome display, a pipe and a
// pager all change the answer, and a grid whose meaning survives none of
// those is hue-only encoding with extra steps. So the heatmap ships as
// words: every cell carries its outcome word, every row carries its
// counts, and the render says so in as many words. The five outcomes are
// distinguishable as text by construction; nothing in the grid is
// perceivable only by colour, and a screen reader reads the same grid a
// founder scans.
//
// # Why counts live in the margins
//
// A cell is one technique in one scenario, and a scenario stages a
// technique once, so a per-cell count would be a permanent 1 — noise
// wearing a number's clothes. The honest counts are the row margins: how
// many scenarios stage this technique, and at which tiers they landed.
// They are printed at the end of every row and sealed into the document
// beside the cells they summarise.

// HeatNA is the cell for a technique a scenario does not stage: a word,
// like the other five, and not a blank — a blank is indistinguishable
// from a rendering gap, and "na" says what it is.
const HeatNA = "na"

// HeatCell is one technique-by-scenario square of the grid.
type HeatCell struct {
	Scenario string `json:"scenario"`
	// Outcome is the scenario's tier, or HeatNA when the scenario does not
	// stage this technique.
	Outcome string `json:"outcome"`
}

// HeatRow is one technique across every scenario the run scored, with the
// margin counts that make the row readable without any colour.
type HeatRow struct {
	Technique string     `json:"technique"`
	Cells     []HeatCell `json:"cells"`
	// Tested is the cells that are not na: the scenarios staging this
	// technique.
	Tested       int `json:"tested"`
	Caught       int `json:"caught_alert"`
	Telemetry    int `json:"telemetry_only"`
	Missed       int `json:"missed"`
	WronglyQuiet int `json:"wrongly_quiet"`
}

// heatWords is the closed cell vocabulary, longest first so the column
// width is the longest word and no cell ever truncates.
var heatWords = []string{OutcomeCaughtTelemetry, OutcomeWronglyQuiet,
	OutcomeCaughtAlert, OutcomeMissed, HeatNA}

func heatWordKnown(w string) bool {
	for _, k := range heatWords {
		if k == w {
			return true
		}
	}
	return false
}

// buildHeatmap folds the rows into the grid. The rows arrive sorted by
// scenario id (sortRows ran), so every HeatRow's cells come out in the
// same order and two documents diff as tables.
func buildHeatmap(rows []Row) []HeatRow {
	if len(rows) == 0 {
		return nil
	}
	staged := map[string]bool{}
	for i := range rows {
		for _, t := range rows[i].Techniques {
			staged[t] = true
		}
	}
	techs := make([]string, 0, len(staged))
	for t := range staged {
		techs = append(techs, t)
	}
	sort.Strings(techs)

	out := make([]HeatRow, 0, len(techs))
	for _, t := range techs {
		hr := HeatRow{Technique: t}
		for i := range rows {
			row := &rows[i]
			if !containsTechnique(row.Techniques, t) {
				hr.Cells = append(hr.Cells, HeatCell{Scenario: row.Scenario,
					Outcome: HeatNA})
				continue
			}
			hr.Cells = append(hr.Cells, HeatCell{Scenario: row.Scenario,
				Outcome: row.Outcome})
			hr.Tested++
			switch row.Outcome {
			case OutcomeCaughtAlert:
				hr.Caught++
			case OutcomeCaughtTelemetry:
				hr.Telemetry++
			case OutcomeMissed:
				hr.Missed++
			case OutcomeWronglyQuiet:
				hr.WronglyQuiet++
			}
		}
		out = append(out, hr)
	}
	return out
}

func containsTechnique(techniques []string, want string) bool {
	for _, t := range techniques {
		if t == want {
			return true
		}
	}
	return false
}

// heatCellWidth is the grid's column width: the longest outcome word plus
// a space, so a cell is never truncated to fit — a truncated word is a
// word a reader cannot read, which is the whole accessibility rule.
func heatCellWidth() int {
	w := 0
	for _, word := range heatWords {
		if len(word) > w {
			w = len(word)
		}
	}
	return w + 1
}

// renderHeatmap is the human face of the grid, on the document's summary.
// Scenarios are the columns, numbered, with a legend above the grid — the
// ids are too long for a header row and a number the reader resolves one
// line up is shorter than an id truncated to fit.
func renderHeatmap(b *strings.Builder, heat []HeatRow) {
	if len(heat) == 0 {
		return
	}
	w := heatCellWidth()
	fmt.Fprintf(b, "  technique heatmap — columns are scenarios, every "+
		"cell says its outcome in words:\n")
	for i, cell := range heat[0].Cells {
		fmt.Fprintf(b, "    %d %s\n", i+1, cell.Scenario)
	}
	// The row-label column fits the longest technique id, so no row's
	// cells are pushed out of the grid by their own label.
	labelW := len("technique")
	for _, hr := range heat {
		if len(hr.Technique) > labelW {
			labelW = len(hr.Technique)
		}
	}
	labelW += 2
	fmt.Fprintf(b, "  %-*s", labelW, "technique")
	for i := range heat[0].Cells {
		fmt.Fprintf(b, "%-*d", w, i+1)
	}
	fmt.Fprintf(b, "\n")
	for _, hr := range heat {
		fmt.Fprintf(b, "  %-*s", labelW, hr.Technique)
		for _, c := range hr.Cells {
			fmt.Fprintf(b, "%-*s", w, c.Outcome)
		}
		fmt.Fprintf(b, " %d/%d caught", hr.Caught, hr.Tested)
		fmt.Fprintf(b, "\n")
	}
	// The accessibility statement travels with the grid, so a reader does
	// not have to trust that the colours they cannot see carried nothing.
	b.WriteString(hang("  ", "every cell carries its outcome word and "+
		"every row its counts; nothing in this grid is colour alone — a "+
		"terminal cannot promise a palette, so the words are the encoding"))
}
