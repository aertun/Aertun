// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/mcp"
	"github.com/aertun/aertun/internal/ops"
)

// The agent interface's face of internal/ops.
//
// Whoever calls through this interface is treated as an agent, whatever the
// token it presents says: some agent host is driving the call, even when the
// credential is a person's. So an operation that changes the store is not
// offered here at all — the core would refuse it anyway, and listing a door
// nobody here may open only invites an agent to try it — and every answer is
// printed labelled, each value beside whether an attacker could have written
// it.

// mcpCaller is a caller on the agent interface.
type mcpCaller struct {
	root string
	c    *Caller
}

func (m mcpCaller) Allowed(a auth.Action, area string) error {
	return authoriseUnder(m.root, m.c, a, area)
}
func (m mcpCaller) Agent() bool  { return true }
func (m mcpCaller) Name() string { return m.c.Name }
func (m mcpCaller) Record(action string, d map[string]string) error {
	return recordE(m.root, audit.Record{Action: action, Resource: "/mcp", Outcome: audit.Success,
		Principal: m.c.Name, Kind: m.c.Kind, Model: m.c.Model, Verified: m.c.Verified, Detail: d})
}

// roleFor is the role an agent is told an operation needs: the inverse of
// actionForRole, so what it is told is what is checked.
func roleFor(a auth.Action) (string, bool) {
	for _, role := range []string{"viewer", "analyst", "responder", "admin"} {
		if got, err := actionForRole(role); err == nil && got == a {
			return role, true
		}
	}
	return "", false
}

// mcpOperation is how an operation is described to an agent, the same on the
// agent interface and the twin; false for one this interface does not offer.
func mcpOperation(op ops.Op) (mcp.Operation, bool) {
	if op.Effect == ops.Change || op.PeopleOnly {
		return mcp.Operation{}, false
	}
	role, ok := roleFor(op.Needs)
	if !ok {
		// An action no role names cannot be told to an agent truthfully.
		return mcp.Operation{}, false
	}
	args := map[string]string{}
	for _, a := range op.Args {
		about := a.About
		if !a.Required {
			about = "optional; " + about
		}
		args[a.Name] = about
	}
	return mcp.Operation{Name: op.Name, Summary: op.Summary, Detail: op.Detail,
		Args: args, Writes: op.Effect != ops.Read, NeedsRole: role, Area: op.Area,
		Keywords: op.Keywords}, true
}

// registerOps offers reg's operations on srv, for caller.
func registerOps(srv *mcp.Server, reg *ops.Registry, root string, caller *Caller) {
	for _, op := range reg.Ops() {
		mop, ok := mcpOperation(op)
		if !ok {
			continue
		}
		name := op.Name
		srv.Register(mop,
			func(in map[string]any) (any, error) {
				raw, err := mcpArgs(in)
				if err != nil {
					return nil, &mcp.Refusal{Reason: err.Error()}
				}
				ans, err := reg.Invoke(name, mcpCaller{root, caller}, raw, time.Now().UTC())
				if err != nil {
					if ops.IsRefusal(err) {
						return nil, &mcp.Refusal{Reason: err.Error()}
					}
					return nil, err
				}
				return ans.Labelled()
			})
	}
}

// mcpArgs turns an agent's JSON arguments into the strings the core reads:
// a string as it is, a whole number in digits, a truth as true or false.
// Anything else — an object, a list, a fraction — is refused rather than
// guessed at.
func mcpArgs(in map[string]any) (map[string]string, error) {
	out := map[string]string{}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch v := in[k].(type) {
		case string:
			out[k] = v
		case bool:
			out[k] = strconv.FormatBool(v)
		case float64:
			if v != float64(int64(v)) {
				return nil, fmt.Errorf("%s is a whole number", k)
			}
			out[k] = strconv.FormatInt(int64(v), 10)
		case nil:
		default:
			return nil, fmt.Errorf("%s is a string, a whole number or true or false", k)
		}
	}
	return out, nil
}
