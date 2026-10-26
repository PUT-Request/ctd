// Package daemon runs the long-lived ctd daemon: it owns all container
// state, serves the HTTP JSON API and the local control socket, and must
// stay running for the CLI to work.
package daemon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"ctd/internal/api"
	"ctd/internal/core"
)

// Run starts the ctd daemon in the foreground on httpAddr with the control
// socket at socketPath. It blocks until the process is killed; closing the
// terminal session therefore stops the daemon (as warned in the banner).
func Run(httpAddr, socketPath string) error {
	// Refuse to double-start: a live daemon holds the socket.
	if c, err := net.Dial("unix", socketPath); err == nil {
		c.Close()
		return fmt.Errorf("ctd daemon is already running (socket %s is live)", socketPath)
	}
	os.Remove(socketPath) // stale socket from a dead daemon
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return err
	}

	srv := &api.Server{Token: api.LoadToken()}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		ln.Close()
		return err
	}
	httpLn, err := net.Listen("tcp", httpAddr)
	if err != nil {
		ln.Close()
		os.Remove(socketPath)
		return err
	}

	fmt.Println("ctd daemon is running — do not close this terminal session if you want to keep running containers.")
	fmt.Printf("  HTTP JSON API:  http://%s  (Authorization: Bearer %s)\n", httpAddr, srv.Token)
	fmt.Printf("  socket:         %s\n", socketPath)

	go func() { _ = srv.ServeUnix(ln) }()
	go gcLoop()

	err = srv.Serve(httpLn)
	os.Remove(socketPath)
	return err
}

// gcLoop keeps the original serve behavior: expire old containers daily.
func gcLoop() {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for range t.C {
		_, _ = core.GC()
	}
}
