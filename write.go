// Copyright 2017 Tamás Gulácsi. All rights reserved.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/pkg/errors"
)

const DefaultStampingPeriod = 10 * time.Second

type writeSyncer interface {
	io.Writer
	Sync() error
}
type framedWriter struct {
	hash.Hash
	w   writeSyncer
	Log func(keyvals ...interface{}) error
}

func (w *framedWriter) Sync() error { return w.w.Sync() }

func (w *framedWriter) Write(p []byte) (int, error) {
	if _, err := fmt.Fprintf(w.w, "%05d:", len(p)); err != nil {
		return 0, err
	}
	n, err := w.w.Write(p)
	if n > 0 {
		w.Hash.Write(p[:n])
	}
	return n, err
}

type authenticatingWriter struct {
	*framedWriter
	buf *bytes.Buffer
	err error

	done chan struct{}
	sync.Mutex

	Sign func([]byte) []byte
	Log  func(keyvals ...interface{}) error
}

func (aw authenticatingWriter) Err() error { return aw.err }

func (aw *authenticatingWriter) WriteMessage(msg Message) error {
	aw.Lock()
	defer aw.Unlock()
	if aw.err != nil {
		return aw.err
	}
	aw.buf.Reset()
	if err := json.NewEncoder(aw.buf).Encode(WrappedMessage{Message: msg}); err != nil {
		return err
	}

	if _, err := aw.framedWriter.Write(aw.buf.Bytes()); err != nil {
		return err
	}
	return nil
}

func (aw *authenticatingWriter) Close() error {
	aw.Lock()
	done := aw.done
	aw.Unlock()
	if done == nil {
		return nil
	}
	select {
	case done <- struct{}{}:
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	case <-time.After(1 * time.Second):
	}
	return nil
}

func newAuthenticatingWriter(w writeSyncer, privateKey ed25519.PrivateKey, stampingPeriod time.Duration, Log func(...interface{}) error) (*authenticatingWriter, error) {
	if Log == nil {
		Log = func(...interface{}) error { return nil }
	}
	if stampingPeriod == 0 {
		stampingPeriod = DefaultStampingPeriod
	}

	aw := &authenticatingWriter{
		framedWriter: &framedWriter{w: w, Hash: newHash(), Log: Log},
		buf:          bytes.NewBuffer(make([]byte, 0, 1024)),
		done:         make(chan struct{}),

		Sign: func(message []byte) []byte {
			return ed25519.Sign(privateKey, message)
		},
		Log: Log,
	}
	if _, err := aw.framedWriter.Write([]byte(Preamble)); err != nil {
		return nil, errors.Wrap(err, "write preamble")
	}
	aw.buf.Reset()
	if err := json.NewEncoder(aw.buf).Encode(PubKey{
		PublicKey:      privateKey.Public().(ed25519.PublicKey),
		StampingPeriod: stampingPeriod,
	}); err != nil {
		return nil, errors.Wrap(err, "marshal public key")
	}
	_, err := aw.framedWriter.Write(aw.buf.Bytes())
	if err != nil {
		return nil, err
	}

	go aw.periodicStamper(stampingPeriod)

	return aw, nil
}
func (aw *authenticatingWriter) periodicStamper(period time.Duration) {
	var stamp Stamp
	if aw.err = aw.stamp(&stamp, time.Now()); aw.err != nil {
		return
	}
	ticks := time.Tick(period)
	for aw.err == nil {
		select {
		case <-aw.done:
			if err := aw.stamp(&stamp, time.Time{}); err != nil && aw.err == nil {
				aw.err = err
			}
			aw.Lock()
			done := aw.done
			aw.done = nil
			aw.Unlock()
			if done != nil {
				close(done)
			}
			return

		case t := <-ticks:
			if err := aw.stamp(&stamp, t); err != nil {
				if aw.err == nil {
					aw.err = err
				}
				return
			}
		}
	}
	if aw.err != nil {
		log.Fatal(aw.err)
	}
}

func (aw *authenticatingWriter) stamp(s *Stamp, t time.Time) error {
	if s == nil {
		s = new(Stamp)
	}
	aw.Lock()
	defer aw.Unlock()

	// timestamp
	if !t.IsZero() {
		aw.buf.Reset()
		if err := json.NewEncoder(aw.buf).Encode(TimeStamp{Time: t}); err != nil {
			return err
		}
		if _, err := aw.framedWriter.Write(aw.buf.Bytes()); err != nil {
			return err
		}
	}

	// signature
	s.Hash = aw.framedWriter.Hash.Sum(s.Hash[:0])
	aw.framedWriter.Hash.Reset()
	s.Signature = aw.Sign(s.Hash)
	aw.buf.Reset()
	if err := json.NewEncoder(aw.buf).Encode(WrappedStamp{Stamp: *s}); err != nil {
		return errors.Wrapf(err, "%#v", *s)
	}
	if _, err := aw.framedWriter.Write(aw.buf.Bytes()); err != nil {
		return err
	}
	if err := aw.framedWriter.Sync(); err != nil {
		return err
	}
	return nil
}

type PubKey struct {
	PublicKey      ed25519.PublicKey `json:"publicKey"`
	StampingPeriod time.Duration     `json:"stampingPeriod"`
}

type WrappedMessage struct {
	Message Message `json:"message"`
}
type Message struct {
	Time   time.Time           `json:"time"`
	Source string              `json:"source"`
	Values map[string][]string `json:"values"`
}

type TimeStamp struct {
	Time time.Time `json:"time"`
}

type WrappedStamp struct {
	Stamp Stamp `json:"stamp"`
}
type Stamp struct {
	Hash      []byte `json:"hash"`
	Signature []byte `json:"signature"`
}

// vim: set fileencoding=utf-8 noet:
