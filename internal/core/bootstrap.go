package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ExecuteBootstrap runs spec.Bootstrapping inside an attached container:
// shares-in, commands (root, sandboxed, per-command timeout), re-sign of
// touched Mach-O executables, priming. Caller decides rollback.
func ExecuteBootstrap(name string, spec *Spec) (int, error) {
	boot := spec.Bootstrapping
	if boot == nil || len(boot.Commands) == 0 {
		return 0, nil
	}
	root := Root(name)
	if err := SyncShares(root, spec, -2, "in"); err != nil {
		return 0, fmt.Errorf("share sync in: %w", err)
	}
	phase := bootstrapPhaseSpec(spec)
	// DNS bridge must be up for bootstrap commands (phase may enable network)
	release, berr := AcquireDNSBridge(root, phase)
	if berr != nil {
		return 0, berr
	}
	defer release()
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	profile := filepath.Join(Dir(name), ".ctd-bootstrap.sb")
	if err := os.WriteFile(profile, []byte(ProfileWith(root, self, phase)), 0o644); err != nil {
		return 0, err
	}
	deadline := time.Duration(boot.Timeout) * time.Second

	for i, command := range boot.Commands {
		out, code, runErr := runBootstrap(self, profile, root, phase, command, deadline)
		Audit("bootstrap", name, []string{command}, code, 0,
			map[string]any{"output": truncate(out, 400)})
		if runErr != nil {
			return 0, fmt.Errorf("bootstrapping command %d: %w", i+1, runErr)
		}
		if code != 0 {
			return 0, fmt.Errorf("bootstrapping command %d failed (exit %d): %s", i+1, code, truncate(out, 400))
		}
	}

	// re-sign Mach-O executables the bootstrap wrote
	since := time.Now().Add(-2 * time.Minute)
	paths := touchedMachO(root, since)
	var signed []string
	for _, p := range paths {
		if err := RunOK("codesign", "-s", "-", "--force", p); err != nil {
			return len(signed), fmt.Errorf("re-sign %s: %w", p, err)
		}
		signed = append(signed, p)
	}
	primePaths(filepath.Join(root, "private/tmp"), signed...)
	return len(signed), nil
}

// bootstrapPhaseSpec resolves the network policy for the bootstrap phase.
func bootstrapPhaseSpec(spec *Spec) *Spec {
	phase := *spec
	if spec.Bootstrapping != nil && spec.Bootstrapping.Network != nil {
		phase.Network = NetworkSpec{Allow: *spec.Bootstrapping.Network}
		phase.Firewall = nil
	}
	phase.Bootstrapping = nil
	return &phase
}

// runBootstrap executes one shell command inside the container as root.
func runBootstrap(self, profile, root string, phase *Spec, command string, timeout time.Duration) (string, int, error) {
	args := []string{"-f", profile, self, "__inner",
		"--root", root, "--user", "root", "--cwd", "/",
		"--", "/bin/sh", "-c", command}
	cmd := exec.Command("sandbox-exec", args...)
	cmd.Env = SanitizeEnv("/Users/me", "/", phase.Env)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return out.String(), -1, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-time.After(timeout):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		waitErr = <-done
		return out.String(), 124, fmt.Errorf("timed out after %s", timeout)
	}
	if waitErr == nil {
		return out.String(), 0, nil
	}
	if ee, ok := waitErr.(*exec.ExitError); ok {
		return out.String(), ee.ExitCode(), nil
	}
	return out.String(), -1, waitErr
}

// touchedMachO collects executable Mach-O files written at/after `since`
// (skips dylibs, the sealed System tree, caps the walk).
func touchedMachO(root string, since time.Time) []string {
	const cap = 500
	var out []string
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "System" || strings.HasPrefix(rel, "System"+string(os.PathSeparator)) {
			return filepath.SkipDir
		}
		if fi.IsDir() {
			return nil
		}
		if len(out) >= cap {
			return filepath.SkipAll
		}
		if fi.Mode()&0o111 == 0 {
			return nil
		}
		if strings.HasSuffix(p, ".dylib") || strings.HasSuffix(p, ".dylib.dSYM") {
			return nil
		}
		if fi.ModTime().Before(since) {
			return nil
		}
		if !isMachO(p) {
			return nil
		}
		out = append(out, p)
		return nil
	})
	return out
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
