// Copyright 2017, 2023 Tamás Gulácsi
//
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package auditlog

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"strconv"
	"time"

	"golang.org/x/crypto/ed25519"
)

var newHash = sha512.New

var (
	ErrHashMismatch   = errors.New("hash mismatch")
	ErrSigMismatch    = errors.New("hash mismatch")
	ErrTooShort       = errors.New("too short")
	ErrPubKeyMissing  = errors.New("public key missing")
	ErrPubKeyMismatch = errors.New("public key mismatch")
	ErrMissingTime    = errors.New("missing time")
)

func Dump(w io.Writer, r io.Reader, publicKey ed25519.PublicKey, logger *slog.Logger) error {
	// try to decompress
	var buf bytes.Buffer
	gr, err := gzip.NewReader(io.TeeReader(r, &buf))
	if err != nil {
		r = io.MultiReader(bytes.NewReader(buf.Bytes()), r)
	} else {
		r = gr
		defer gr.Close()
	}

	fr := &framedReader{br: bufio.NewReader(r), Hash: newHash(), Logger: logger}
	if !fr.Next() {
		if err = fr.Err(); err == nil {
			err = io.EOF
		}
		return err
	}
	if !fr.Next() || !bytes.HasPrefix(fr.Bytes(), []byte(`{"publicKey":`)) {
		return fmt.Errorf("%q: %w", string(fr.Bytes()), ErrPubKeyMissing)
	}
	var pub PubKey
	if err := json.Unmarshal(fr.Bytes(), &pub); err != nil {
		return fmt.Errorf("%q: %w", string(fr.Bytes()), err)
	}
	if !bytes.Equal(publicKey, pub.PublicKey) {
		return ErrPubKeyMismatch
	}
	ar := &authenticatedReader{
		framedReader:   fr,
		StampingPeriod: pub.StampingPeriod,
		Verify: func(message, sig []byte) error {
			if ed25519.Verify(pub.PublicKey, message, sig) {
				return nil
			}
			return ErrSigMismatch
		},
		Logger: logger,
	}
	for fr.Next() {
		var msg Message
		found, err := ar.Parse(&msg, fr.Bytes())
		if err != nil {
			return err
		}
		//Log("found", found, "err", err, "msg", msg, "bytes", string(fr.Bytes()))
		if !found {
			continue
		}

		fmt.Fprintf(w, "%s [%s]: %s\n", msg.Time.Format(time.RFC3339), msg.Source, msg.Values)
	}
	if err = fr.Err(); errors.Is(err, io.EOF) {
		err = nil
	}
	return err
}

type authenticatedReader struct {
	*framedReader
	StampingPeriod time.Duration
	lastStampTime  time.Time
	scratch        []byte
	Verify         func(message, sig []byte) error
	*slog.Logger
}

// Verify the data hash and signature, and return whether this should be processed (realm message).
func (ar *authenticatedReader) Parse(msg *Message, p []byte) (found bool, err error) {
	if len(p) < 3 {
		return false, fmt.Errorf("%q: %w", string(p), ErrTooShort)
	}
	switch string(p[:3]) {
	case `{"m`:
		var wm WrappedMessage
		if err := json.Unmarshal(p, &wm); err != nil {
			return false, fmt.Errorf("%q: %w", string(p), err)
		}
		*msg = wm.Message
		return true, nil

	case `{"t`:
		var ts TimeStamp
		if err := json.Unmarshal(p, &ts); err != nil {
			return false, fmt.Errorf("%q: %w", string(p), err)
		}
		if !ar.lastStampTime.IsZero() {
			if dur := ts.Time.Sub(ar.lastStampTime); !(dur < ar.StampingPeriod*3/2) {
				return false, fmt.Errorf("last=%s actual=%s (dur=%s, required=%s): %w", ar.lastStampTime, ts.Time, dur, ar.StampingPeriod, ErrMissingTime)
			}
		}
		ar.lastStampTime = ts.Time

	case `{"s`:
		var ws WrappedStamp
		if err := json.Unmarshal(p, &ws); err != nil {
			return false, fmt.Errorf("%q: %w", string(p), err)
		}
		ar.scratch = ar.framedReader.prevHash
		ar.framedReader.Hash = ar.framedReader.NextHash
		if !bytes.Equal(ws.Stamp.Hash, ar.scratch) {
			return false, fmt.Errorf("got=%s wanted=%s: %w",
				base64.URLEncoding.EncodeToString(ar.scratch),
				base64.URLEncoding.EncodeToString(ws.Stamp.Hash),
				ErrHashMismatch)
		}
		return false, ar.Verify(ws.Stamp.Hash, ws.Stamp.Signature)

	default:
		return false, fmt.Errorf("unknown message %q", p)
	}
	return false, nil
}

type framedReader struct {
	br   *bufio.Reader
	Hash hash.Hash
	err  error
	*slog.Logger

	prevHash []byte
	NextHash hash.Hash

	scratch []byte
	bytes   []byte
}

func (fr *framedReader) Err() error { return fr.err }

func (fr *framedReader) Next() bool {
	if fr.err != nil {
		return false
	}

	// read length prefix
	var length uint64
	if cap(fr.scratch) < 5+1 {
		fr.scratch = make([]byte, 1<<16)
	}

	if _, fr.err = io.ReadFull(fr.br, fr.scratch[:6]); fr.err != nil {
		return false
	}
	if fr.scratch[5] == ':' {
		if length, fr.err = strconv.ParseUint(string(fr.scratch[:5]), 10, 64); fr.err != nil {
			fr.err = fmt.Errorf("%q: %w", string(fr.scratch), fr.err)
			return false
		}
	}
	if length == 0 || length > 99999 {
		fr.err = fmt.Errorf("no length found in %q", fr.scratch[:6])
		return false
	}

	// read message
	if cap(fr.scratch) < int(length) {
		fr.scratch = make([]byte, int(length))
	}
	fr.bytes = fr.scratch[:int(length)]
	if _, fr.err = io.ReadFull(fr.br, fr.bytes); fr.err != nil {
		return false
	}
	fr.prevHash = fr.Hash.Sum(fr.prevHash[:0])
	fr.Hash.Write(fr.bytes)
	fr.NextHash = newHash()
	fr.NextHash.Write(fr.bytes)

	return true
}

func (fr *framedReader) Bytes() []byte {
	return fr.bytes
}

// vim: set fileencoding=utf-8 noet:
