// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows

package sshctl

import (
	"bytes"
	"io"
	"testing"
	"time"
)

const TestString = "AABBCCDDEEFFGG"

func TestRunWithBuffers(t *testing.T) {
	server := newServer(t)
	defer server.Shutdown()
	sshmux := server.Run()

	sess := NewSession(sshmux)
	inb := bytes.NewBufferString(TestString)
	var outb bytes.Buffer
	var errb bytes.Buffer
	sess.Stdout = &outb
	sess.Stderr = &errb
	sess.Stdin = inb
	err := sess.Run("cat")

	if err != nil {
		t.Fatalf("Got err: %s", err)
	}
	if outb.String() != TestString {
		t.Fatalf("expected response \"%s\" but got \"%s\"", TestString, outb.String())
	}

	sess = NewSession(sshmux)
	outb.Reset()
	sess.Stdout = &outb
	sess.Stderr = &errb
	sess.Stdin = inb
	err = sess.Run("echo -n " + TestString)

	if outb.String() != TestString {
		t.Fatalf("expected response \"%s\" but got \"%s\"", TestString, outb.String())
	}

}

func TestRunWithStdinPipe(t *testing.T) {
	server := newServer(t)
	defer server.Shutdown()
	sshmux := server.Run()
	sess := NewSession(sshmux)

	var outb bytes.Buffer
	stdin, err := sess.StdinPipe()
	stdout, err := sess.StdoutPipe()
	go func() {
		inb := bytes.NewBufferString(TestString)
		io.Copy(stdin, inb)
		t.Logf("iocopy stdin done")
		stdin.Close()
	}()
	go func() {
		io.Copy(&outb, stdout)
		t.Logf("iocopy stdout done")
	}()
	err = sess.Run("cat")
	if err != nil {
		t.Fatalf("Got err: %s", err)
	}
	if outb.String() != TestString {
		t.Fatalf("expected response \"%s\" but got \"%s\"", TestString, outb.String())
	}
}

func TestSessionClose(t *testing.T) {
	server := newServer(t)
	defer server.Shutdown()
	sshmux := server.Run()
	var outb bytes.Buffer

	sess := NewSession(sshmux)
	sess.Stdout = &outb
	ch := make(chan error)
	go func() { ch <- sess.Run("echo -n " + TestString + "; sleep 10") }()
	time.Sleep(1 * time.Second)

	// Assert that Close terminates Run() instantaneously
	sess.Close()
	select {
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Close() did not abort Run()")
	case err := <-ch:
		if err.Error() != "Session aborted" {
			t.Fatalf("Unexpected error. Got %s", err)
		}
	}
	if outb.String() != TestString {
		t.Fatalf("expected response \"%s\" but got \"%s\"", TestString, outb.String())
	}
}

func TestCombinedOutput(t *testing.T) {
	server := newServer(t)
	defer server.Shutdown()
	sshmux := server.Run()

	sess := NewSession(sshmux)
	out, err := sess.CombinedOutput("echo -n " + TestString + "| tee /dev/stderr")
	if err != nil {
		t.Fatalf("Got err: %s", err)
	}
	if string(out) != TestString+TestString {
		t.Fatalf("expected response \"%s\" but got \"%s\"", TestString+TestString, out)
	}

}
