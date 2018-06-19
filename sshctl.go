// Copyright 2018 Marco Pfatschbacher. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The Session API is modeled after "golang.org/x/crypto/ssh/session.go"
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sshctl

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"sync"
)

// NewSession prepares a new Session on top of an ssh(1) "ControlMaster" process.
// The given path points towards the ssh "ControlPath"
func NewSession(path string) *Session {
	s := &Session{sshctlpath: path}
	return s
}

type Session struct {
	// Stdin specifies the remote process's standard input.
	// If Stdin is nil, the remote process reads from an empty
	// bytes.Buffer.
	Stdin io.Reader

	// Stdout and Stderr specify the remote process's standard
	// output and error.
	//
	// If either is nil, Run connects the corresponding file
	// descriptor to an instance of ioutil.Discard. There is a
	// fixed amount of buffering that is shared for the two streams.
	// If either blocks it may eventually cause the remote
	// command to block.
	Stdout io.Writer
	Stderr io.Writer

	// Local files of a mux session
	lmuxStdin  *os.File
	lmuxStdout *os.File
	lmuxStderr *os.File

	// Remote files of a mux session
	// These are passed to the ssh process
	rmuxStdin  *os.File
	rmuxStdout *os.File
	rmuxStderr *os.File

	copyFuncs []func() error
	errors    chan error // one send per copyFunc

	sshctlpath string // the ssh control unix socket path
	ctrlconn   *net.UnixConn
	ctrlReqid  int
	ctrlSessid int
	term       string
	started    bool // true once Start, Run or Shell is invoked.

	// true if pipe method is active
	stdinpipe, stdoutpipe, stderrpipe bool

	// stdinPipeWriter is non-nil if StdinPipe has not been called
	// and Stdin was specified by the user; it is the write end of
	// a pipe connecting Session.Stdin to the stdin channel.
	stdinPipeWriter io.WriteCloser

	exitStatus chan error
	aborted    chan bool
}

// Start runs cmd on the remote host. Typically, the remote
// server passes cmd to the shell for interpretation.
// A Session only accepts one call to Run, Start or Shell.
func (s *Session) Start(cmd string) error {
	if s.started {
		return errors.New("ssh: session already started")
	}

	if err := s.openCtrlConn(); err != nil {
		return err
	}
	if err := s.requestMuxSession(cmd); err != nil {
		return err
	}

	s.exitStatus = make(chan error, 1)
	s.aborted = make(chan bool, 1)
	go func() {
		s.exitStatus <- s.wait()
	}()

	return s.start()
}
func (s *Session) Close() error {
	/*
		XXX?
			s.lmuxStdin.Close()
			s.lmuxStdout.Close()
			s.lmuxStderr.Close()

			s.rmuxStdin.Close()
			s.rmuxStdout.Close()
			s.rmuxStderr.Close()
	*/
	if s.ctrlconn != nil {
		s.ctrlconn.Close()
	}
	if s.lmuxStderr != nil {
		s.lmuxStderr.Close()
	}
	if s.lmuxStdout != nil {
		s.lmuxStdout.Close()
	}
	s.aborted <- true
	return nil
}

// RequestPty requests the association of a pty with the session on the remote host.
func (s *Session) RequestPty(term string) error {
	s.term = term
	return nil
}

// Shell starts a login shell on the remote host. A Session only
// accepts one call to Run, Start, Shell, Output, or CombinedOutput.
func (s *Session) Shell() error {
	if s.started {
		return errors.New("ssh: session already started")
	}
	if err := s.openCtrlConn(); err != nil {
		return err
	}
	if err := s.requestMuxSession(""); err != nil {
		return err
	}

	s.exitStatus = make(chan error, 1)
	go func() {
		s.exitStatus <- s.wait()
	}()

	return s.start()
}

// Run runs cmd on the remote host. Typically, the remote
// server passes cmd to the shell for interpretation.
// A Session only accepts one call to Run, Start, Shell, Output,
// or CombinedOutput.
//
// The returned error is nil if the command runs, has no problems
// copying stdin, stdout, and stderr, and exits with a zero exit
// status.
//
// If the remote server does not send an exit status, an error of type
// *ExitMissingError is returned. If the command completes
// unsuccessfully or is interrupted by a signal, the error is of type
// *ExitError. Other error types may be returned for I/O problems.
func (s *Session) Run(cmd string) error {
	err := s.Start(cmd)
	if err != nil {
		return err
	}
	return s.Wait()
}

// Output runs cmd on the remote host and returns its standard output.
func (s *Session) Output(cmd string) ([]byte, error) {
	if s.Stdout != nil {
		return nil, errors.New("ssh: Stdout already set")
	}
	var b bytes.Buffer
	s.Stdout = &b
	err := s.Run(cmd)
	return b.Bytes(), err
}

type singleWriter struct {
	b  bytes.Buffer
	mu sync.Mutex
}

func (w *singleWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

// CombinedOutput runs cmd on the remote host and returns its combined
// standard output and standard error.
func (s *Session) CombinedOutput(cmd string) ([]byte, error) {
	if s.Stdout != nil {
		return nil, errors.New("ssh: Stdout already set")
	}
	if s.Stderr != nil {
		return nil, errors.New("ssh: Stderr already set")
	}
	var b singleWriter
	s.Stdout = &b
	s.Stderr = &b
	err := s.Run(cmd)
	return b.b.Bytes(), err
}

// Wait waits for the remote command to exit.
//
// The returned error is nil if the command runs, has no problems
// copying stdin, stdout, and stderr, and exits with a zero exit
// status.
//
// If the remote server does not send an exit status, an error of type
// *ExitMissingError is returned. If the command completes
// unsuccessfully or is interrupted by a signal, the error is of type
// *ExitError. Other error types may be returned for I/O problems.
func (s *Session) Wait() error {
	if !s.started {
		return errors.New("ssh: session not started")
	}
	var waitErr error
	// s.ctrlconn.Close() does not abort a blocking s.ctrlconn.Read()
	// Selecting on an separate channel as a workaround
	select {
	case waitErr = <-s.exitStatus:
	case <-s.aborted:
		waitErr = errors.New("Session aborted")
	}

	if s.stdinPipeWriter != nil {
		s.stdinPipeWriter.Close()
	}
	var copyError error
	for _ = range s.copyFuncs {
		if err := <-s.errors; err != nil && copyError == nil {
			copyError = err
		}
	}
	if waitErr != nil {
		return waitErr
	}
	return copyError
}

func (s *Session) start() error {
	s.started = true

	type F func(*Session)
	for _, setupFd := range []F{(*Session).stdin, (*Session).stdout, (*Session).stderr} {
		setupFd(s)
	}

	s.errors = make(chan error, len(s.copyFuncs))
	for _, fn := range s.copyFuncs {
		go func(fn func() error) {
			s.errors <- fn()
		}(fn)
	}
	return nil
}

func (s *Session) stdin() {
	if s.stdinpipe {
		return
	}
	var stdin io.Reader
	if s.Stdin == nil {
		stdin = new(bytes.Buffer)
	} else {
		r, w := io.Pipe()
		go func() {
			_, err := io.Copy(w, s.Stdin)
			w.CloseWithError(err)
		}()
		stdin, s.stdinPipeWriter = r, w
	}
	s.copyFuncs = append(s.copyFuncs, func() error {
		_, err := io.Copy(s.lmuxStdin, stdin)
		if err1 := s.lmuxStdin.Close(); err == nil && err1 != io.EOF {
			err = err1
		}
		return err
	})
}

func (s *Session) stdout() {
	if s.stdoutpipe {
		return
	}
	if s.Stdout == nil {
		s.Stdout = ioutil.Discard
	}
	s.copyFuncs = append(s.copyFuncs, func() error {
		_, err := io.Copy(s.Stdout, s.lmuxStdout)
		return err
	})
}
func (s *Session) stderr() {
	if s.stderrpipe {
		return
	}
	if s.Stderr == nil {
		s.Stderr = ioutil.Discard
	}
	s.copyFuncs = append(s.copyFuncs, func() error {
		_, err := io.Copy(s.Stderr, s.lmuxStderr)
		return err
	})
}

// StdinPipe returns a pipe that will be connected to the
// remote command's standard input when the command starts.
func (s *Session) StdinPipe() (io.WriteCloser, error) {
	if s.Stdin != nil {
		return nil, errors.New("ssh: Stdin already set")
	}
	if s.started {
		return nil, errors.New("ssh: StdinPipe after process started")
	}
	s.stdinpipe = true
	s.rmuxStdin, s.lmuxStdin, _ = os.Pipe()
	return s.lmuxStdin, nil
}

// StdoutPipe returns a pipe that will be connected to the
// remote command's standard output when the command starts.
// There is a fixed amount of buffering that is shared between
// stdout and stderr streams. If the StdoutPipe reader is
// not serviced fast enough it may eventually cause the
// remote command to block.
func (s *Session) StdoutPipe() (io.Reader, error) {
	if s.Stdout != nil {
		return nil, errors.New("ssh: Stdout already set")
	}
	if s.started {
		return nil, errors.New("ssh: StdoutPipe after process started")
	}
	s.stdoutpipe = true
	s.lmuxStdout, s.rmuxStdout, _ = os.Pipe()
	return s.lmuxStdout, nil
}

// StderrPipe returns a pipe that will be connected to the
// remote command's standard error when the command starts.
// There is a fixed amount of buffering that is shared between
// stdout and stderr streams. If the StderrPipe reader is
// not serviced fast enough it may eventually cause the
// remote command to block.
func (s *Session) StderrPipe() (io.Reader, error) {
	if s.Stderr != nil {
		return nil, errors.New("ssh: Stderr already set")
	}
	if s.started {
		return nil, errors.New("ssh: StderrPipe after process started")
	}
	s.stderrpipe = true
	s.lmuxStderr, s.rmuxStderr, _ = os.Pipe()
	return s.lmuxStderr, nil
}

// An ExitError reports unsuccessful completion of a remote command.
type ExitError struct {
	Waitmsg
}

func (e *ExitError) Error() string {
	return e.Waitmsg.String()
}

// Waitmsg stores the information about an exited remote command
// as reported by Wait.
type Waitmsg struct {
	status int
	signal string
	msg    string
	lang   string
}

// ExitStatus returns the exit status of the remote command.
func (w Waitmsg) ExitStatus() int {
	return w.status
}

// Signal returns the exit signal of the remote command if
// it was terminated violently.
func (w Waitmsg) Signal() string {
	return w.signal
}

// Msg returns the exit message given by the remote command
func (w Waitmsg) Msg() string {
	return w.msg
}

// Lang returns the language tag. See RFC 3066
func (w Waitmsg) Lang() string {
	return w.lang
}

func (w Waitmsg) String() string {
	str := fmt.Sprintf("Process exited with status %v", w.status)
	if w.signal != "" {
		str += fmt.Sprintf(" from signal %v", w.signal)
	}
	if w.msg != "" {
		str += fmt.Sprintf(". Reason was: %v", w.msg)
	}
	return str
}
