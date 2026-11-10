// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
	"github.com/aertun/aertun/internal/proving"
)

// provingMarker is planted in the name of a rule a detection proof checks:
// text whoever submitted the rule chose.
const provingMarker = "IGNORE-PREVIOUS"

// provingRig is a console with the proving ground's real operations over a
// store holding two proofs: a proven verdicts proof, whose words are this
// program's, and a detection proof of a rule whose name is somebody else's.
func provingRig(t *testing.T, role auth.Role) (srv *Server, token, root string, recorded *[]string) {
	t.Helper()
	srv, token = asRole(t, role)
	root = t.TempDir()
	var recs []string
	srv.Proving = &ProvingGround{Ops: proving.Ops(root),
		Record: func(by, action, resource string, d map[string]string) error {
			recs = append(recs, by+" "+action)
			return nil
		}}
	k, _ := pack.GenerateKey()
	pub, _ := json.Marshal(k.PublicKey())
	keep := func(st *proof.Statement) {
		env, err := proof.Seal(st, k)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(env)
		if _, _, err := proofstore.Keep(root, body, pub, "dana", proofstore.OriginHere, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	keep(verdictsProof(t, 0))
	rule, err := os.ReadFile("../detect/pack/okta.mfa-reset.json")
	if err != nil {
		t.Fatal(err)
	}
	det, err := proof.ProveDetection(proof.DetectionInput{RuleName: provingMarker + "-<b>bold</b>.json",
		Rule: rule, Program: "test", Now: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	keep(det)
	return srv, token, root, &recs
}

func verdictsProof(t *testing.T, falseClosures int) *proof.Statement {
	t.Helper()
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	n := 300
	st, err := proof.ProveVerdicts(proof.VerdictsInput{Source: "charlotte", Labels: proof.LabelsPeople,
		Since: t0, Until: t0.Add(7 * 24 * time.Hour), Tolerance: 0.01,
		Lines: []byte("{}\n"), Considered: n, Counted: n, Alerts: n,
		FalseClosures:  proof.Count{K: falseClosures, N: n},
		ReviewCoverage: proof.Count{K: n, N: n}, DeliveredFirst: proof.Count{K: n, N: n},
		Agreement: proof.Count{K: n - falseClosures, N: n}, Abstentions: proof.Count{K: 0, N: n},
		FalseClosed: closedAlerts(falseClosures), Program: "test", Now: t0.Add(8 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func closedAlerts(k int) []string {
	var out []string
	for i := range k {
		out = append(out, "ldt:"+strconv.Itoa(1000+i))
	}
	return out
}

// The screen shows each proof as the operation labelled it: the verdicts
// proof's claim as this program's words, the detection proof's — which names
// a rule somebody else named — escaped and marked as written outside.
func TestTheProofsScreenShowsWhatTheOperationLabelled(t *testing.T) {
	srv, token, _, _ := provingRig(t, auth.RoleViewer)
	body := getPage(t, srv, "/proving/proofs", token)
	if strings.Contains(body, "<b>bold</b>") {
		t.Fatal("a rule's name reached the page unescaped")
	}
	i := strings.Index(body, provingMarker)
	if i < 0 {
		t.Fatalf("the detection proof is not listed:\n%s", body)
	}
	if !strings.Contains(body[i:i+400], "untrusted") {
		t.Errorf("text from outside is shown without its mark: %s", body[i:i+400])
	}
	j := strings.Index(body, "closed as false-positive or benign")
	if j < 0 {
		t.Fatalf("the verdicts proof is not listed")
	}
	if end := strings.Index(body[j:], "</td>"); strings.Contains(body[j:j+end], "untrusted") {
		t.Errorf("this program's own words are marked as written outside")
	}
	for _, want := range []string{"proven", "Proving ground", "/proving/proofs?kind=verdicts"} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen does not show %q", want)
		}
	}
	// Each proof, in full: its checks, and the same marks.
	for _, m := range regexp.MustCompile(`href="/proving/proofs/([0-9a-f]{24})"`).FindAllStringSubmatch(body, -1) {
		page := getPage(t, srv, "/proving/proofs/"+m[1], token)
		if !strings.Contains(page, "Checks") || !strings.Contains(page, "Signed by key") {
			t.Errorf("proof %s's page:\n%s", m[1], page)
		}
		if strings.Contains(page, provingMarker) && !strings.Contains(page, "untrusted") {
			t.Errorf("proof %s shows outside text unmarked", m[1])
		}
		if strings.Contains(page, "<b>bold</b>") {
			t.Errorf("proof %s shows a rule's name unescaped", m[1])
		}
	}
}

// The screen asks nothing itself beyond who is signed in: whether they may
// see the proofs is the operation's question, asked through the core, so a
// person without view in the security area is refused here as on every face.
func TestTheProofsScreenIsAuthorisedByTheCore(t *testing.T) {
	srv, token, _, _ := provingRig(t, auth.RoleViewer)
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{Principal: "someone", Role: auth.RoleViewer, Resource: "/settings"}); err != nil {
		t.Fatal(err)
	}
	srv.Policy = pol
	w := get(t, srv, "/proving/proofs", token)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "charlotte") {
		t.Errorf("a person without view in the security area got %d:\n%s", w.Code, w.Body.String())
	}
}

// Keeping a proof through the form is the core's keep_proof: checked against
// its key, recorded first in the person's name, and refused to a viewer.
func TestKeepingAProofThroughTheConsole(t *testing.T) {
	srv, token, root, recorded := provingRig(t, auth.RoleAnalyst)
	k, _ := pack.GenerateKey()
	env, _ := proof.Seal(verdictsProof(t, 20), k)
	envBody, _ := json.Marshal(env)
	pubBody, _ := json.Marshal(k.PublicKey())
	send := func(srv *Server, token string, pub []byte) *httptest.ResponseRecorder {
		var b bytes.Buffer
		mw := multipart.NewWriter(&b)
		fw, _ := mw.CreateFormFile("envelope_file", "proof.json")
		fw.Write(envBody)
		mw.WriteField("public_key", string(pub))
		mw.Close()
		req := httptest.NewRequest(http.MethodPost, "/proving/proofs/keep", &b)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	w := send(srv, token, pubBody)
	loc := w.Header().Get("Location")
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/proving/proofs/") || strings.Contains(loc, "e=") {
		t.Fatalf("keep: %d %s", w.Code, loc)
	}
	if len(*recorded) != 1 || *recorded != nil && (*recorded)[0] != "someone proof.kept" {
		t.Errorf("recorded %v", *recorded)
	}
	page := getPage(t, srv, strings.SplitN(loc, "?", 2)[0], token)
	if !strings.Contains(page, "refuted") || !strings.Contains(page, "false closure: ldt:") {
		t.Errorf("the kept proof's page:\n%s", page)
	}
	// A key that did not sign it: nothing kept.
	other, _ := pack.GenerateKey()
	otherPub, _ := json.Marshal(other.PublicKey())
	before, _ := proofstore.List(root)
	if w := send(srv, token, otherPub); !strings.Contains(w.Header().Get("Location"), "e=") {
		t.Errorf("a proof with the wrong key was kept: %s", w.Header().Get("Location"))
	}
	if after, _ := proofstore.List(root); len(after) != len(before) {
		t.Errorf("%d kept, %d before", len(after), len(before))
	}
	// A viewer may read and may not keep.
	vsrv, vtoken, _, vrec := provingRig(t, auth.RoleViewer)
	if w := send(vsrv, vtoken, pubBody); !strings.Contains(w.Header().Get("Location"), "e=") || len(*vrec) != 0 {
		t.Errorf("a viewer kept a proof: %s", w.Header().Get("Location"))
	}
	// A record that cannot be written stops the change.
	srv.Proving.Record = func(string, string, string, map[string]string) error { return errors.New("log full") }
	env2, _ := proof.Seal(verdictsProof(t, 5), k)
	envBody, _ = json.Marshal(env2)
	if w := send(srv, token, pubBody); !strings.Contains(w.Header().Get("Location"), "e=") {
		t.Errorf("a change was made without its record: %s", w.Header().Get("Location"))
	}
}

// A credential that acts for an agent is an agent's, on this face as on the
// others.
func TestAnOnBehalfOfCredentialIsAnAgentsHere(t *testing.T) {
	if (consoleCaller{p: principal{}}).Agent() {
		t.Error("a person's own session read as an agent's")
	}
	if !(consoleCaller{p: principal{Proof: auth.Token{Act: []string{"dana", "agent:triage"}}}}).Agent() {
		t.Error("an on-behalf-of credential read as a person's")
	}
}
