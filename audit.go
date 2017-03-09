// Copyright 2017 Tamás Gulácsi. All rights reserved.

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

func main() {
	if err := Main(); err != nil {
		log.Fatal(err)
	}
}

const Preamble = `All data is framed by prefixing with the length in ASCII decimal, 5 digits (prefixed with zeros), then ':'.

Data is hashed with SHA-512, and these hashes are signed with Ed25519.

Real data starts right after this preamble.
`

func Main() error {
	flagAddr := flag.String("addr", "127.0.0.1:8901", "address to listen on")
	flagPrivKey := flag.String("key", "audit.key", "private key to use for signing")
	flagLog := flag.String("log", fmt.Sprintf("audit-%s.log", time.Now().Format("20060102_150405")), "log file")
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
		log.Println(errors.Wrap(err, *flagPrivKey), fmt.Sprintf("size=%d", len(b)))
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
			return errors.Wrap(err, flag.Arg(1))
		}
		defer fh.Close()
		return Dump(os.Stdout, fh, privateKey.Public().(ed25519.PublicKey), Log)
	}

	ln, err := net.Listen("tcp", *flagAddr)
	log.Println("Listening on " + *flagAddr)
	if err != nil {
		return errors.Wrap(err, *flagAddr)
	}

	fh, err := os.OpenFile(*flagLog, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0640)
	if err != nil {
		return errors.Wrap(err, *flagLog)
	}
	defer fh.Close()

	aw, err := newAuthenticatingWriter(fh, privateKey, *flagStampingPeriod, Log)
	if err != nil {
		return err
	}
	defer aw.Close()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, os.Interrupt)
	defer close(sigCh)
	go func() {
		for s := range sigCh {
			aw.Close()
			log.Fatalf("%s received, closing down.", s)
		}
	}()

	h := handler{
		PrivateKey:           privateKey,
		authenticatingWriter: aw,
		Forward:              func([]byte) error { return nil },
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
			return errors.Wrap(err, *flagSyslog)
		}
		h.Forward = func(line []byte) error {
			_, err := lw.Write(line)
			return err
		}
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go h.handleConnection(conn)
	}

	return fh.Close()
}

type handler struct {
	ed25519.PrivateKey
	*authenticatingWriter
	Forward func([]byte) error
}

var bufPool = sync.Pool{New: func() interface{} { return bytes.NewBuffer(make([]byte, 1024)) }}

func (h handler) handleConnection(conn net.Conn) error {
	defer conn.Close()

	var msg Message
	source := conn.RemoteAddr().String()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
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
		if err = h.authenticatingWriter.WriteMessage(msg); err != nil {
			log.Println(err)
			fmt.Fprintf(conn, "-ERROR %v\n", err)
			return err
		}

		if err := h.Forward(line); err != nil {
			log.Println(err)
			fmt.Fprintf(conn, "-ERROR %v\n", err)
			continue
		}
		conn.Write([]byte("+OK\n"))
	}
	return nil
}

// vim: set fileencoding=utf-8 noet:
