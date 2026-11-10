// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/aertun/aertun/internal/ops"

// The agent interface's answers are internal/ops's, under the short names
// its operations were written with: one type, so an answer the twin labels
// and one the console fences are the same value with the same decision on it.
type answer = ops.Answer

func ours(v any) *answer                                 { return ops.Ours(v) }
func outside(s string) *answer                           { return ops.Outside(s) }
func object() *answer                                    { return ops.Object() }
func oursText(s string) *answer                          { return ops.OursText(s) }
func listOf[T any](in []T, each func(T) *answer) *answer { return ops.ListOf(in, each) }
func byKey[K ~string, V any](m map[K]V, each func(V) *answer) *answer {
	return ops.ByKey(m, each)
}
