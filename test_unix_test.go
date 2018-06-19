// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd plan9

package sshctl

// functional test harness for unix.

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
	"text/template"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/testdata"
)

var ssh_configs = map[string]string{
	"sshd_config": `
Protocol 2
HostKey {{.Dir}}/id_rsa
HostKey {{.Dir}}/id_dsa
HostKey {{.Dir}}/id_ecdsa
HostCertificate {{.Dir}}/id_rsa-cert.pub
Pidfile {{.Dir}}/sshd.pid
SyslogFacility AUTH
#LogLevel DEBUG2
LoginGraceTime 120
PermitRootLogin no
StrictModes no
PubkeyAuthentication yes
AuthorizedKeysFile	{{.Dir}}/authorized_keys
TrustedUserCAKeys {{.Dir}}/id_ecdsa.pub
IgnoreRhosts yes
HostbasedAuthentication no
PubkeyAcceptedKeyTypes=*
`,
	"ssh_config": `
ProxyCommand -
ControlMaster yes
ControlPath {{.Dir}}/ctrl.sock
IdentityFile {{.Dir}}/id_rsa
UpdateHostKeys no
UserKnownHostsFile {{.Dir}}/known_hosts
BatchMode yes
`,
}

type server struct {
	t          *testing.T
	cleanup    func() // executed during Shutdown
	configfile string
	testdir    string
	sshdcmd    *exec.Cmd
	sshcmd     *exec.Cmd
	output     bytes.Buffer // holds stderr from sshd/ssh processes

	// Control Socket to ssh
	ctrlSock string
}

func username() string {
	var username string
	if user, err := user.Current(); err == nil {
		username = user.Username
	} else {
		// user.Current() currently requires cgo. If an error is
		// returned attempt to get the username from the environment.
		log.Printf("user.Current: %v; falling back on $USER", err)
		username = os.Getenv("USER")
	}
	if username == "" {
		panic("Unable to get username")
	}
	return username
}

func (s *server) TryRun() (string, error) {
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		s.t.Skipf("skipping test: %v", err)
	}
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		s.t.Skipf("skipping test: %v", err)
	}

	s.sshdcmd = exec.Command(sshd, "-f", s.testdir+"/sshd_config", "-i", "-e")
	s.sshcmd = exec.Command(ssh, "-F", s.testdir+"/ssh_config", "-N", username()+"@dummy")
	s.sshdcmd.Stdin, _ = s.sshcmd.StdoutPipe()
	s.sshcmd.Stdin, _ = s.sshdcmd.StdoutPipe()
	s.sshdcmd.Stderr = &s.output
	s.sshcmd.Stderr = &s.output
	if err := s.sshdcmd.Start(); err != nil {
		s.t.Fail()
		s.Shutdown()
		s.t.Fatalf("s.sshdcmd.Start: %v", err)
	}
	if err := s.sshcmd.Start(); err != nil {
		s.t.Fail()
		s.Shutdown()
		s.t.Fatalf("s.sshcmd.Start: %v", err)
	}
	s.ctrlSock = s.testdir + "/ctrl.sock"

	// Wait for control socket
	for i := 1; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		if _, err := os.Stat(s.ctrlSock); err == nil {
			return s.ctrlSock, nil
		}
	}
	s.t.Fatalf("ssh did not create control socket %s", s.ctrlSock)

	return "", nil
}

func (s *server) Run() string {
	conn, err := s.TryRun()
	if err != nil {
		s.t.Fail()
		s.Shutdown()
		s.t.Fatalf("ssh.Client: %v", err)
	}
	return conn
}

func (s *server) Shutdown() {
	for _, cmd := range []*exec.Cmd{s.sshdcmd, s.sshcmd} {
		if cmd != nil && cmd.Process != nil {
			// Don't check for errors; if it fails it's most
			// likely "os: process already finished", and we don't
			// care about that. Use os.Interrupt, so child
			// processes are killed too.
			cmd.Process.Signal(os.Interrupt)
			cmd.Wait()
		}
	}
	if s.t.Failed() {
		// log any output from sshd process
		s.t.Logf("sshd: %s", s.output.String())
	}
	s.cleanup()
}

func writeFile(path string, contents []byte) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(contents); err != nil {
		panic(err)
	}
}

// newServer returns a new mock ssh--->sshd server.
func newServer(t *testing.T) *server {
	if testing.Short() {
		t.Skip("skipping test due to -short")
	}
	dir, err := ioutil.TempDir("", "sshctltest")
	if err != nil {
		t.Fatal(err)
	}
	for cname, conf := range ssh_configs {
		f, err := os.Create(filepath.Join(dir, cname))
		if err != nil {
			t.Fatal(err)
		}
		configTmpl := template.Must(template.New("").Parse(conf))
		err = configTmpl.Execute(f, map[string]string{
			"Dir": dir,
		})
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	var known_hosts bytes.Buffer
	for k, v := range testdata.PEMBytes {
		filename := "id_" + k
		writeFile(filepath.Join(dir, filename), v)
		writeFile(filepath.Join(dir, filename+".pub"), ssh.MarshalAuthorizedKey(testPublicKeys[k]))
		known_hosts.WriteString("dummy ")
		known_hosts.Write(ssh.MarshalAuthorizedKey(testPublicKeys[k]))
		known_hosts.WriteString("\n")
	}
	writeFile(filepath.Join(dir, "known_hosts"), known_hosts.Bytes())

	for k, v := range testdata.SSHCertificates {
		filename := "id_" + k + "-cert.pub"
		writeFile(filepath.Join(dir, filename), v)
	}

	var authkeys bytes.Buffer
	for k, _ := range testdata.PEMBytes {
		authkeys.Write(ssh.MarshalAuthorizedKey(testPublicKeys[k]))
	}
	writeFile(filepath.Join(dir, "authorized_keys"), authkeys.Bytes())

	return &server{
		t:       t,
		testdir: dir,
		cleanup: func() {
			if err := os.RemoveAll(dir); err != nil {
				t.Error(err)
			}
		},
	}
}
