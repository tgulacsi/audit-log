// Copyright 2017 Tamás Gulácsi
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
