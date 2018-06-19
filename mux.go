// Copyright 2018 Marco Pfatschbacher. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sshctl

import (
	"encoding/binary"
	"fmt"
	"github.com/ftrvxmtrx/fd"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"net"
	"os"
)

// ssh mux protocol messages
// cf: https://github.com/openbsd/src/blob/master/usr.bin/ssh/mux.c
const (
	muxVersion    = 4
	muxMsgHello   = 1
	muxNewSession = 0x10000002
	muxAliveCheck = 0x10000004

	muxIsAlive       = 0x80000005
	muxSessionOpened = 0x80000006
	muxTtyAllocFail  = 0x80000008
	muxExitMessage   = 0x80000004
)

type muxNewSessionMsg struct {
	Request       uint32
	RequestId     uint32
	ReservedStr   string
	TtyFlags      uint32
	ForwardX11    uint32
	ForwardAgent  uint32
	SubSystemFlag uint32
	EscapeChar    uint32
	Term          string
	Command       string
}

type muxMsg struct {
	Request uint32
	Param   uint32
}

func (s *Session) readPacket() ([]byte, error) {
	lenbuf := make([]byte, 4)
	_, err := io.ReadAtLeast(s.ctrlconn, lenbuf, 4)
	if err != nil {
		return nil, fmt.Errorf("Unable to read from control socket: %v", err)
	}
	len := binary.BigEndian.Uint32(lenbuf)

	packet := make([]byte, len)
	_, err = io.ReadAtLeast(s.ctrlconn, packet, int(len))
	if err != nil {
		return nil, fmt.Errorf("Unable to read from control socket: %v", err)
	}
	return packet, nil
}

func (s *Session) writePacket(req []byte) (err error) {
	msg := make([]byte, 4+len(req))
	binary.BigEndian.PutUint32(msg, uint32(len(req)))
	copy(msg[4:], req)
	if _, err = s.ctrlconn.Write(msg); err != nil {
		return err
	}
	return nil
}

func packetPopInt(buf *[]byte) (int, error) {
	if len(*buf) < 4 {
		return -1, fmt.Errorf("buffer too short")
	}
	res := binary.BigEndian.Uint32(*buf)
	*buf = (*buf)[4:]
	return int(res), nil
}

func (s *Session) recvInts(count int) ([]int, error) {
	var packet []byte
	var err error
	msgs := make([]int, 0)
	if packet, err = s.readPacket(); err != nil {
		return nil, err
	}
	var msg int
	for ; count > 0; count-- {
		if msg, err = packetPopInt(&packet); err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
	}
	return msgs, nil
}

func (s *Session) openCtrlConn() error {
	var raddr *net.UnixAddr
	var err error
	if raddr, err = net.ResolveUnixAddr("unix", s.sshctlpath); err != nil {
		return err
	}
	if s.ctrlconn, err = net.DialUnix("unix", nil, raddr); err != nil {
		return err
	}
	return nil
}

func (s *Session) sshMuxHello() error {
	var msgs []int
	var err error

	if msgs, err = s.recvInts(2); err != nil {
		return err
	}
	if msgs[0] != muxMsgHello || msgs[1] != muxVersion {
		return fmt.Errorf("Incompatible Hello packet received")
	}
	m := &muxMsg{}
	m.Request = muxMsgHello
	m.Param = muxVersion
	buf := ssh.Marshal(m)
	if err = s.writePacket(buf); err != nil {
		return err
	}
	return nil
}

func (s *Session) sshMuxAliveCheck() error {
	var msgs []int
	var err error

	m := &muxMsg{}
	m.Request = muxAliveCheck
	m.Param = uint32(s.ctrlReqid)
	buf := ssh.Marshal(m)
	if err = s.writePacket(buf); err != nil {
		return err
	}
	if msgs, err = s.recvInts(3); err != nil {
		return err
	}
	if msgs[0] != muxIsAlive {
		return fmt.Errorf("Expected ALIVE, got: 0x%x", msgs[0])
	}
	if msgs[1] != s.ctrlReqid {
		return fmt.Errorf("out of sequence reply: 0x%x", msgs[0])
	}
	//sshpid = msgs[2]
	s.ctrlReqid++
	return nil
}

func (s *Session) sshMuxNewSession(cmd string) error {
	nms := &muxNewSessionMsg{}
	nms.Request = uint32(muxNewSession)
	nms.RequestId = uint32(s.ctrlReqid)
	nms.ReservedStr = ""
	nms.EscapeChar = uint32(0xffffffff) // disable escape char
	nms.Term = ""
	nms.TtyFlags = uint32(0)
	if s.term != "" {
		nms.Term = s.term
		nms.TtyFlags = uint32(1)
	}
	nms.Command = cmd
	buf := ssh.Marshal(nms)
	if err := s.writePacket(buf); err != nil {
		return err
	}
	return nil
}

func (s *Session) sshMuxPassFileDescriptors() error {
	var msgs []int
	var err error

	// SSH expects us to pass file descriptors.
	// If the the user did provide an os.File, use it directly.
	// Otherwise create a Pipe() and pass one end.
	if sf, ok := s.Stdin.(*os.File); ok {
		s.rmuxStdin = sf
		s.stdinpipe = true
	} else if s.lmuxStdin == nil {
		//  r, w, err = os.Pipe
		if s.rmuxStdin, s.lmuxStdin, err = os.Pipe(); err != nil {
			return err
		}
	}
	if sf, ok := s.Stdout.(*os.File); ok {
		s.rmuxStdout = sf
		s.stdoutpipe = true
	} else if s.lmuxStdout == nil {
		if s.lmuxStdout, s.rmuxStdout, err = os.Pipe(); err != nil {
			return err
		}
	}
	if sf, ok := s.Stderr.(*os.File); ok {
		s.rmuxStderr = sf
		s.stderrpipe = true
	} else if s.lmuxStderr == nil {
		if s.lmuxStderr, s.rmuxStderr, err = os.Pipe(); err != nil {
			return err
		}
	}
	fd.Put(s.ctrlconn, s.rmuxStdin)  //stdin
	fd.Put(s.ctrlconn, s.rmuxStdout) //stdout
	fd.Put(s.ctrlconn, s.rmuxStderr) //stderr

	if msgs, err = s.recvInts(3); err != nil {
		return err
	}
	if msgs[0] != muxSessionOpened {
		return fmt.Errorf("Expected muxSessionOpened, got: 0x%x", msgs[0])
	}
	if msgs[1] != s.ctrlReqid {
		return fmt.Errorf("out of sequence reply: 0x%x", msgs[0])
	}
	s.ctrlSessid = msgs[2]
	s.ctrlReqid++
	return nil
}

func (s *Session) makeRawTerm() error {
	fd := int(s.rmuxStdin.Fd())
	st, err := terminal.GetState(fd)
	// Restore has to be done by the user
	raw, err := terminal.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("MakeRaw err: %v", err)
	}
	if *st != *raw {
		return fmt.Errorf("MakeRaw state was %v expected %v", *raw, *st)
	}
	return nil
}

func (s *Session) requestMuxSession(cmd string) error {
	var err error

	s.ctrlReqid = 0
	if err = s.sshMuxHello(); err != nil {
		return err
	}
	if err = s.sshMuxAliveCheck(); err != nil {
		return err
	}
	if err = s.sshMuxNewSession(cmd); err != nil {
		return err
	}
	if err = s.sshMuxPassFileDescriptors(); err != nil {
		return err
	}
	if s.term != "" {
		if err = s.makeRawTerm(); err != nil {
			return err
		}
	}

	// On created pipes, close the remote end from our side.
	// This needs to happen after makeRawTerm()
	if s.lmuxStdin != nil {
		s.rmuxStdin.Close()
	}
	if s.lmuxStdout != nil {
		s.rmuxStdout.Close()
	}
	if s.lmuxStderr != nil {
		s.rmuxStderr.Close()
	}
	return nil
}

func (s *Session) wait() error {
	wm := Waitmsg{status: -1}
	var buf []byte
	var err error
	var mtype, sid int

	exit_seen := false
	for {
		if buf, err = s.readPacket(); err != nil {
			break
		}
		if mtype, err = packetPopInt(&buf); err != nil {
			break
		}

		switch mtype {
		case muxTtyAllocFail:
			if sid, err = packetPopInt(&buf); err != nil {
				break
			}
			if sid != s.ctrlSessid {
				wm.msg = fmt.Sprintf("unknown session id: myid %d theirs %d", s.ctrlSessid, sid)
				break
			}
		case muxExitMessage:
			if sid, err = packetPopInt(&buf); err != nil {
				break
			}
			if sid != s.ctrlSessid {
				wm.msg = fmt.Sprintf("unknown session id: myid %d theirs %d", s.ctrlSessid, sid)
				break
			}
			if exit_seen {
				wm.msg = "exit seen twice"
				break
			}
			if wm.status, err = packetPopInt(&buf); err != nil {
				break
			}
			exit_seen = true
		default:
			// XXX read error string from packet
			//checkErr(fmt.Errorf("master returned error: XXX"))
			break
		}
	}

	if wm.status == 0 {
		return nil
	}
	if wm.status == -1 {
		// exit-status was never sent from server
		return &ExitMissingError{}
	}
	s.ctrlconn.Close()

	return &ExitError{wm}
}

// ExitMissingError is returned if a session is torn down cleanly, but
// the server sends no confirmation of the exit status.
type ExitMissingError struct{}

func (e *ExitMissingError) Error() string {
	return "wait: remote command exited without exit status or exit signal"
}
