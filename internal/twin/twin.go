// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package twin is the file a context twin answers from: one recorded case,
// sealed under a digest of its exact bytes.
//
// A replay is only a replay if what answers it cannot move. The agent
// interface reads the store, and the store changes — findings arrive,
// people decide, rules are tuned — so an investigation run against it twice
// is two investigations. A twin answers from a file instead, and the file
// says what it holds: a format name, the sha256 of the recorded body, and
// the body. A file whose body does not hash to the digest it carries is
// refused rather than served, so an edit, a truncation or a copy that went
// wrong shows up as a refusal and never as a different answer.
//
// The digest is an integrity check, not a signature: whoever can edit the
// file can write a new digest beside the edit. What it does is pin a replay
// to the bytes it was run against, so a result that names the digest names
// exactly what the agent was shown. Who recorded the file, and when, is in
// the audit log of the store it was recorded from.
//
// What the body holds is the caller's to decide. This package seals it,
// bounds it, and reads it back strictly.
package twin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/aertun/aertun/internal/proof"
)

// Format names the file's shape and its version. A file naming any other
// format is refused, because a body read under the wrong shape is a body
// read wrongly.
const Format = "aertun/twin/v1"

// MaxSize bounds a twin file both when it is written and when it is read.
// One limit for both, so that every snapshot this program writes is one it
// can read back: a recording too large to replay would be a recording of
// nothing.
const MaxSize = 64 << 20

// file is the outer shape. Snapshot is kept as the raw bytes it arrived
// as, because the digest is over those bytes and not over any re-encoding
// of them.
type file struct {
	Format   string          `json:"format"`
	Digest   string          `json:"digest"`
	Snapshot json.RawMessage `json:"snapshot"`
}

// Digest is the name a body goes by: sha256 over its exact bytes.
func Digest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Seal encodes body and writes it out with its digest, returning the file's
// bytes and the digest. The file is assembled by hand rather than by
// encoding a struct, so that the bytes the digest is taken over are exactly
// the bytes that land in the file.
func Seal(body any) ([]byte, string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, "", err
	}
	if len(raw) == 0 || raw[0] != '{' {
		return nil, "", errors.New("a snapshot is an object; this body is not one")
	}
	digest := Digest(raw)
	head := `{"format":"` + Format + `","digest":"` + digest + `","snapshot":`
	const tail = "}\n"
	if size := len(head) + len(raw) + len(tail); size > MaxSize {
		return nil, "", fmt.Errorf("the snapshot is %d bytes, more than the %d "+
			"a twin reads; nothing was written", size, MaxSize)
	}
	var b bytes.Buffer
	b.Grow(len(head) + len(raw) + len(tail))
	b.WriteString(head)
	b.Write(raw)
	b.WriteString(tail)
	return b.Bytes(), digest, nil
}

// Open checks a file's format and digest and decodes its body into into,
// returning the digest. Both layers are decoded strictly: a field this
// program does not know is a file it would misread, and trailing bytes are
// something the digest did not cover. The bytes are the caller's, already
// in memory; Read is what bounds a file on its way in.
func Open(raw []byte, into any) (string, error) {
	var f file
	if err := strict(raw, &f); err != nil {
		return "", fmt.Errorf("not a twin snapshot: %w", err)
	}
	if f.Format != Format {
		return "", fmt.Errorf("the file says it is %q, and this program reads %q",
			f.Format, Format)
	}
	if len(f.Snapshot) == 0 || f.Snapshot[0] != '{' {
		return "", errors.New("the file holds no snapshot object")
	}
	if got := Digest(f.Snapshot); got != f.Digest {
		return "", fmt.Errorf("the snapshot does not match its digest: the file "+
			"says %s and its bytes are %s, so it was changed after it was "+
			"recorded and is refused rather than served", f.Digest, got)
	}
	if err := strict(f.Snapshot, into); err != nil {
		return "", fmt.Errorf("the snapshot does not read as one: %w", err)
	}
	return f.Digest, nil
}

// Read is Open over a file on disk, read within MaxSize.
func Read(path string, into any) (string, error) {
	raw, err := proof.ReadBounded(path, MaxSize)
	if err != nil {
		return "", err
	}
	return Open(raw, into)
}

// strict decodes exactly one JSON value with no field the target lacks.
func strict(raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("there is more after the snapshot than the snapshot")
	}
	return nil
}
