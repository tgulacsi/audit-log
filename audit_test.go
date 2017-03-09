package main

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"
)

func TestAudit(t *testing.T) {
	fh, err := ioutil.TempFile("", "audit-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(fh.Name())
	defer fh.Close()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	Log := func(keyvals ...interface{}) error {
		t.Log(keyvals...)
		return nil
	}
	aw, err := newAuthenticatingWriter(fh, privateKey, 100*time.Millisecond, Log)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}

	fh.Close()
	if fh, err = os.Open(fh.Name()); err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	if err := Dump(os.Stdout, fh, publicKey, Log); err != nil {
		t.Fatal(err)
	}
}
