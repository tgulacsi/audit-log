// Copyright 2017, 2021 Tamás Gulácsi
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
	"bufio"
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tgulacsi/audit-log/auditlog"
	"golang.org/x/crypto/ed25519"
)

func main() {
	if err := Main(); err != nil {
		log.Fatal(err)
	}
}

func Main() error {
	flagAddr := flag.String("addr", "127.0.0.1:8901", "address to listen on")
	flagPrivKey := flag.String("key", "audit.key", "private key to use for signing")
	flagLog := flag.String("log", fmt.Sprintf("audit-%s.log.gz", time.Now().Format("20060102_150405")), "log file")
	flagStampingPeriod := flag.Duration("stamping-period", 60*time.Second, "stamping (and flushing) period")
	flagVerbose := flag.Bool("v", false, "verbose logging")
	flagSyslog := flag.String("syslog", "", "syslog to forward logs to. Format: [tcp:|udp:]host[:port], or 'local' to use the system logger.")
	flagSyslogTag := flag.String("syslog-tag", "audit-log", "syslog tag to use")
	flag.Parse()

	var privateKey ed25519.PrivateKey
	b, err := ioutil.ReadFile(*flagPrivKey)
	if err == nil && len(b) == ed25519.PrivateKeySize {
		privateKey = b
	} else {
		log.Printf("privKey=%v size=%d: %+v", *flagPrivKey, len(b), err)
		if _, privateKey, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return err
		}
		if err := ioutil.WriteFile(*flagPrivKey, privateKey, 0400); err != nil {
			return err
		}
	}

	var Log func(...interface{}) error
	if *flagVerbose {
		Log = func(keyvals ...interface{}) error {
			log.Println(keyvals...)
			return nil
		}
	}

	if flag.Arg(0) == "dump" {
		fh, err := os.Open(flag.Arg(1))
		if err != nil {
			return fmt.Errorf("%q: %w", flag.Arg(1), err)
		}
		defer fh.Close()
		return auditlog.Dump(os.Stdout, fh, privateKey.Public().(ed25519.PublicKey), Log)
	}

	ln, err := net.Listen("tcp", *flagAddr)
	log.Println("Listening on " + *flagAddr)
	if err != nil {
		return fmt.Errorf("%q: %w", *flagAddr, err)
	}

	aw, err := auditlog.NewAuthenticatingFileWriter(*flagLog, privateKey, *flagStampingPeriod, Log)
	if err != nil {
		return err
	}
	defer aw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer close(sigCh)
	go func() {
		sig := <-sigCh
		cancel()
		_ = aw.Close()
		log.Fatalf("%s received, closing down.", sig)
		if p, _ := os.FindProcess(os.Getpid()); p != nil {
			time.Sleep(time.Second)
			_ = p.Signal(sig)
		}
	}()

	h := handler{
		PrivateKey:    privateKey,
		messageWriter: aw,
		Forward:       func([]byte) error { return nil },
	}
	if *flagSyslog != "" {
		var lw *syslog.Writer
		prio, tag := syslog.LOG_NOTICE|syslog.LOG_LOCAL1, *flagSyslogTag
		if *flagSyslog == "local" {
			lw, err = syslog.New(prio, tag)
		} else {
			network, addr := "udp", *flagSyslog
			if strings.HasPrefix(addr, "tcp:") {
				network, addr = "tcp", addr[4:]
			} else if strings.HasPrefix(addr, "udp:") {
				network, addr = "udp", addr[4:]
			}
			if i := strings.LastIndexByte(addr, ':'); i < 0 {
				if network == "tcp" {
					addr += ":6514"
				} else {
					addr += ":514"
				}
			}
			*flagSyslog = network + ":" + addr
			lw, err = syslog.Dial(network, addr, prio, tag)
		}
		if err != nil {
			return fmt.Errorf("%q: %w", *flagSyslog, err)
		}
		h.Forward = func(line []byte) error {
			_, err := lw.Write(line)
			return err
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go func() { _ = h.handleConnection(ctx, conn) }()
	}
}

type messageWriter interface {
	WriteMessage(auditlog.Message) error
	io.Closer
}

type handler struct {
	ed25519.PrivateKey
	messageWriter
	Forward func([]byte) error
}

func (h handler) handleConnection(ctx context.Context, conn net.Conn) error {
	defer conn.Close()

	var msg auditlog.Message
	source := conn.RemoteAddr().String()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		qry, err := url.ParseQuery(scanner.Text())
		if err != nil {
			log.Println(err)
			fmt.Fprintf(conn, "-ERROR %s\n", url.QueryEscape(err.Error()))
			continue
		}
		msg.Time = time.Now()
		msg.Source = source
		msg.Values = qry
		if err = h.messageWriter.WriteMessage(msg); err != nil {
			log.Println(err)
			fmt.Fprintf(conn, "-ERROR %v\n", err)
			return err
		}

		if err := h.Forward(line); err != nil {
			log.Println(err)
			fmt.Fprintf(conn, "-ERROR %v\n", err)
			continue
		}
		if _, err := conn.Write([]byte("+OK\n")); err != nil {
			log.Println(err)
			continue
		}
	}
	return nil
}

// vim: set fileencoding=utf-8 noet:
