// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package twin

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type body struct {
	Case  string   `json:"case"`
	Items []string `json:"items"`
}

func sealed(t *testing.T) ([]byte, string) {
	t.Helper()
	raw, digest, err := Seal(body{Case: "spray against admin-dana", Items: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	return raw, digest
}

// A sealed file opens to what was sealed, under the digest of its body's
// exact bytes, and the same body seals to the same bytes every time.
func TestASealedSnapshotOpensToWhatWasSealed(t *testing.T) {
	raw, digest := sealed(t)
	again, _ := sealed(t)
	if !bytes.Equal(raw, again) {
		t.Fatal("the same body sealed to different bytes")
	}
	var got body
	d, err := Open(raw, &got)
	if err != nil {
		t.Fatal(err)
	}
	if d != digest || got.Case != "spray against admin-dana" || len(got.Items) != 2 {
		t.Fatalf("opened %s %+v", d, got)
	}
	want := Digest([]byte(`{"case":"spray against admin-dana","items":["a","b"]}`))
	if digest != want {
		t.Fatalf("the digest %s is not over the body's bytes (%s)", digest, want)
	}
}

// One byte of the body changed, the digest left as it was: refused, and
// refused as a mismatch rather than read as a different case.
func TestASnapshotWhoseBodyWasChangedIsRefused(t *testing.T) {
	raw, _ := sealed(t)
	edited := bytes.Replace(raw, []byte("admin-dana"), []byte("admin-dant"), 1)
	if bytes.Equal(edited, raw) {
		t.Fatal("the edit did not happen")
	}
	var got body
	_, err := Open(edited, &got)
	if err == nil || !strings.Contains(err.Error(), "does not match its digest") {
		t.Fatalf("an edited snapshot was not refused for its digest: %v", err)
	}
	if got.Case != "" {
		t.Fatal("an edited snapshot was decoded before it was refused")
	}
}

// Everything else a file could be that Seal never writes is refused: the
// wrong format, a field nobody knows (outside or inside the body, the
// digest recomputed so only strictness can refuse it), bytes after the
// file, and a body that is not an object.
func TestAnythingSealDidNotWriteIsRefused(t *testing.T) {
	raw, digest := sealed(t)
	inner := `{"case":"x","items":[],"extra":1}`
	notObject := "null"
	for name, file := range map[string]string{
		"another format": strings.Replace(string(raw), Format, "aertun/twin/v0", 1),
		"an unknown outer field": strings.Replace(string(raw), `"digest"`,
			`"signed":true,"digest"`, 1),
		"an unknown body field": `{"format":"` + Format + `","digest":"` +
			Digest([]byte(inner)) + `","snapshot":` + inner + "}",
		"trailing bytes": string(raw) + `{"more":1}`,
		"a body not an object": `{"format":"` + Format + `","digest":"` +
			Digest([]byte(notObject)) + `","snapshot":null}`,
		"no digest": strings.Replace(string(raw), digest, "", 1),
	} {
		var got body
		if _, err := Open([]byte(file), &got); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

// A file larger than a twin reads is refused at the read, before it is
// held whole; Seal will not write one either, so every snapshot written can
// be read back.
func TestASnapshotTooLargeIsNeitherWrittenNorRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxSize + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	var got body
	if _, err := Read(path, &got); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("an oversized file was not refused for its size: %v", err)
	}
	if _, _, err := Seal(body{Case: strings.Repeat("a", MaxSize)}); err == nil ||
		!strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("an oversized snapshot was sealed: %v", err)
	}
}
