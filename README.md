# sshctl
A Go client library to control an SSH multiplexing master process.

### Example
Start a regular ssh(1) command with a ControlMaster socket in `/var/tmp/mux.sock`:

```
$ ssh -fN -oControlMaster=yes -oControlPath=/var/tmp/mux.sock host
```
With sshctl you can run request additional SSH sessions from this socket:

```go
import "github.com/mpfz0r/sshctl"

sess := sshctl.NewSession("/var/tmp/mux.sock")

var outb bytes.Buffer
sess.Stdout = &outb
err := sess.Run("cat /etc/motd")

if err != nil {
	fmt.Println("Got err: ", err)
} else {
	fmt.Println("Remote motd: ", outb.String())
}
```

