package core

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Provenance priming: each tool is executed once at its real host path,
// outside the chroot, before container use. Idempotent per mount device.

// mountDevice returns the device node backing path (e.g. "/dev/disk11s1"),
// or "" if path is not a mountpoint.
func mountDevice(path string) string {
	out, _ := runMount()
	marker := " on " + path + " ("
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, marker); i >= 0 {
			return strings.Fields(line)[0]
		}
	}
	return ""
}

func primeMarker(name, dev string) string {
	d := strings.TrimPrefix(filepath.Base(dev), "")
	return filepath.Join(Dir(name), ".primed-"+d)
}

// PrimeTools executes each curated tool once outside the chroot; anything
// that runs indefinitely is killed after the timeout.
func PrimeTools(root string) {
	var paths []string
	for _, t := range CuratedTools {
		p := filepath.Join(root, t)
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		if fi.Mode()&0o111 == 0 {
			continue
		}
		paths = append(paths, p)
	}
	primePaths(filepath.Join(root, "private/tmp"), paths...)
}

// primePaths executes each binary once outside the chroot; cwd is the
// container tmp (idempotent per process).
func primePaths(cwd string, paths ...string) {
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			cmd := exec.Command(p)
			cmd.Stdin = strings.NewReader("") // EOF immediately
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			if isDir(cwd) {
				cmd.Dir = cwd
			}
			if err := cmd.Start(); err != nil {
				return
			}
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(250 * time.Millisecond):
				_ = cmd.Process.Kill()
				<-done
			}
		}(path)
	}
	wg.Wait()
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// ensurePrimed primes the container's tools if this mount device has not
// been primed yet. Caller must hold attachMu.
func ensurePrimed(name string) {
	root := Root(name)
	// key on the image mount (root itself is a plain dir in thin-root geometry)
	dev := mountDevice(filepath.Join(root, "img"))
	if dev == "" {
		return // not mounted — nothing to prime
	}
	marker := primeMarker(name, dev)
	if _, err := os.Stat(marker); err == nil {
		return // already primed for this mount instance
	}
	PrimeTools(root)
	// record priming for this mount instance
	_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)), 0o644)
	if entries, err := os.ReadDir(Dir(name)); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".primed-") && e.Name() != filepath.Base(marker) {
				_ = os.Remove(filepath.Join(Dir(name), e.Name()))
			}
		}
	}
}
