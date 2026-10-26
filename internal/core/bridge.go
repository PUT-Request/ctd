package core

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// DNS bridge: exposes the host /var/run/mDNSResponder socket inside the
// container tree so chrooted processes can resolve names. Relays payloads
// and SCM_RIGHTS file descriptors both ways.

const hostMDNS = "/private/var/run/mDNSResponder"

var (
	bridgeMu    sync.Mutex
	bridgeAlive = map[string]bool{}
)

// AcquireDNSBridge ensures a working DNS bridge for the container.
// Returns a release func (idempotent). No-op when DNS is disabled.
func AcquireDNSBridge(root string, spec *Spec) (func(), error) {
	if spec == nil || !spec.dnsEnabled() {
		return func() {}, nil
	}
	sock := filepath.Join(root, "var", "run", "mDNSResponder")

	bridgeMu.Lock()
	defer bridgeMu.Unlock()

	if bridgeAlive[root] {
		return func() {}, nil
	}
	if _, err := os.Stat(sock); err == nil {
		if c, err := net.DialTimeout("unix", sock, 300*time.Millisecond); err == nil {
			c.Close()
			return func() {}, nil // a live bridge (this or another process) serves it
		}
		_ = os.Remove(sock) // stale socket
	}
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		return nil, err
	}

	lfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	sa := &unix.SockaddrUnix{Name: sock}
	if err := unix.Bind(lfd, sa); err != nil {
		unix.Close(lfd)
		return nil, fmt.Errorf("dns bridge bind: %w", err)
	}
	if err := unix.Listen(lfd, 64); err != nil {
		unix.Close(lfd)
		return nil, err
	}
	if err := os.Chmod(sock, 0o666); err != nil {
		unix.Close(lfd)
		return nil, err
	}
	bridgeAlive[root] = true

	go acceptLoop(lfd)

	release := func() {
		bridgeMu.Lock()
		defer bridgeMu.Unlock()
		if bridgeAlive[root] {
			delete(bridgeAlive, root)
			unix.Close(lfd)
			// stale file; next process rebinds
		}
	}
	return release, nil
}

func acceptLoop(lfd int) {
	for {
		cfd, _, err := unix.Accept(lfd)
		if err != nil {
			return // listener closed
		}
		go serveConn(cfd)
	}
}

// serveConn relays one client connection to the host mDNSResponder.
func serveConn(cfd int) {
	defer unix.Close(cfd)
	hfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return
	}
	defer unix.Close(hfd)
	if err := unix.Connect(hfd, &unix.SockaddrUnix{Name: hostMDNS}); err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); fdRelay(cfd, hfd) }()
	go func() { defer wg.Done(); fdRelay(hfd, cfd) }()
	wg.Wait()
}

// blog logs relay messages when CTD_BRIDGE_LOG=<path> is set.
var bridgeLogPath = os.Getenv("CTD_BRIDGE_LOG")

func blog(format string, args ...any) {
	if bridgeLogPath == "" {
		return
	}
	f, err := os.OpenFile(bridgeLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, format+"\n", args...)
}

// fdRelay copies one direction, re-sending received file descriptors.
func fdRelay(from, to int) {
	buf := make([]byte, 16*1024)
	oob := make([]byte, 4096)
	for {
		n, oobn, _, _, err := unix.Recvmsg(from, buf, oob, 0)
		if n == 0 && oobn == 0 {
			return // EOF
		}
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return
		}
		var rights []byte
		var passFds []int
		nfds := 0
		if oobn > 0 {
			cmsgs, perr := unix.ParseSocketControlMessage(oob[:oobn])
			if perr != nil {
				blog("dir=%d->%d n=%d oob=%d CMSG_PARSE_ERR=%v", from, to, n, oobn, perr)
			}
			for _, cm := range cmsgs {
				if cm.Header.Level == unix.SOL_SOCKET && cm.Header.Type == unix.SCM_RIGHTS {
					fds, ferr := unix.ParseUnixRights(&cm)
					if ferr == nil && len(fds) > 0 {
						nfds = len(fds)
						rights = unix.UnixRights(fds...)
						passFds = fds // stays open until Sendmsg delivers
					} else {
						blog("dir=%d->%d RIGHTS_PARSE_ERR=%v", from, to, ferr)
					}
				}
			}
		}
		blog("dir=%d->%d n=%d oob=%d fds=%d", from, to, n, oobn, nfds)
		if serr := unix.Sendmsg(to, buf[:n], rights, nil, 0); serr != nil {
			blog("dir=%d->%d SEND_ERR=%v rights=%d", from, to, serr, len(rights))
			for _, f := range passFds {
				unix.Close(f)
			}
			return
		}
		// drop our copies after delivery
		for _, f := range passFds {
			unix.Close(f)
		}
	}
}
