package core

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ExecResult is the outcome of a containerized command.
type ExecResult struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
}

// ExecOptions control a containerized run.
type ExecOptions struct {
	Cwd      string            // chroot-relative cwd (default /Users/me)
	Env      map[string]string // extra environment
	Stdin    string            // piped stdin
	Timeout  time.Duration     // 0 = no timeout
	Rlimits  map[string]uint64 // overrides: cpu, fsize, nproc, nofile
	Username string            // run as this user inside (default nobody)
}

// execShared is the single execution path used by Exec (captured) and
// StreamExec (streaming): attach, TTL + disk gates, Seatbelt profile,
// shares-in, prime, DNS bridge, sandbox-exec, wait (timeout/abort),
// audit, shares-out.
func execShared(source, name string, argv []string, opts ExecOptions,
	stdin io.Reader, stdout, stderr io.Writer, abort <-chan struct{},
	started func(pid int)) (*ExecResult, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("no command given")
	}
	if err := Attach(name); err != nil {
		return nil, err
	}
	if c, err := Describe(name); err == nil && c.Expired {
		return nil, fmt.Errorf("container %q expired", name)
	}
	root := Root(name)
	cm, merr := LoadMeta(name)
	if merr != nil {
		cm = &meta{}
	}
	spec := cm.effectiveSpec()
	uid := cm.effectiveUid()
	if spec.User == "root" {
		uid = 0
	}
	if err := CheckDiskQuota(name, spec); err != nil {
		return nil, err
	}

	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	profile, err := WriteProfile(root, self, spec)
	if err != nil {
		return nil, err
	}
	if serr := SyncShares(root, spec, cm.effectiveUid(), "in"); serr != nil {
		return nil, fmt.Errorf("share sync in: %w", serr)
	}
	if signed := signShareExes(cm.Name, root, spec); len(signed) > 0 {
		primePaths(filepath.Join(root, "private/tmp"), signed...)
	}
	release, berr := AcquireDNSBridge(root, spec)
	if berr != nil {
		return nil, berr
	}
	defer release()

	args := []string{"-f", profile, self, "__inner", "--root", root, "--uid", fmt.Sprintf("%d", uid)}
	cwd := opts.Cwd
	if cwd == "" {
		cwd = spec.Workdir
	}
	if cwd != "" {
		args = append(args, "--cwd", cwd)
	}
	if opts.Username != "" {
		args = append(args, "--user", opts.Username)
	}
	rl := spec.Rlimits()
	for k, v := range opts.Rlimits {
		rl[k] = v
	}
	for k, v := range rl {
		args = append(args, "--rlimit", fmt.Sprintf("%s=%d", k, v))
	}
	args = append(args, "--")
	args = append(args, argv...)

	cmd := exec.Command("sandbox-exec", args...)
	env := spec.Env
	for k, v := range opts.Env {
		env[k] = v
	}
	cmd.Env = SanitizeEnv(spec.Home, cwd, env)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	if started != nil {
		started(cmd.Process.Pid) // Setpgid: pid == pgid
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timedOut, aborted := false, false
	var waitErr error
	if opts.Timeout > 0 {
		select {
		case waitErr = <-done:
		case <-time.After(opts.Timeout):
			timedOut = true
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			waitErr = <-done
		case <-abort:
			aborted = true
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			waitErr = <-done
		}
	} else {
		select {
		case waitErr = <-done:
		case <-abort:
			aborted = true
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			waitErr = <-done
		}
	}

	exitCode := 0
	switch {
	case timedOut:
		exitCode = 124
	case aborted:
		exitCode = 130
	case waitErr != nil:
		if ee, ok := waitErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return nil, waitErr
		}
	}
	res := &ExecResult{ExitCode: exitCode, DurationMs: time.Since(start).Milliseconds()}
	Audit(source, name, argv, exitCode, time.Since(start),
		map[string]any{"timed_out": timedOut, "aborted": aborted})
	if serr := SyncShares(root, spec, cm.effectiveUid(), "out"); serr != nil {
		res.Stderr += "\n[ctd] share sync out: " + serr.Error() + "\n"
	}
	return res, nil
}

// Exec runs a command captured (stdout/stderr collected).
func Exec(source, name string, argv []string, opts ExecOptions) (*ExecResult, error) {
	var stdout, stderr strings.Builder
	res, err := execShared(source, name, argv, opts, strings.NewReader(opts.Stdin), &stdout, &stderr, nil, nil)
	if err != nil {
		return nil, err
	}
	res.Stdout = stdout.String()
	res.Stderr = stderr.String()
	return res, nil
}

// StreamExec runs a command with caller-supplied streams (daemon streaming)
// and an abort channel that kills the tree on client disconnect.
func StreamExec(source, name string, argv []string, opts ExecOptions,
	stdin io.Reader, stdout, stderr io.Writer, abort <-chan struct{},
	started func(pid int)) (*ExecResult, error) {
	return execShared(source, name, argv, opts, stdin, stdout, stderr, abort, started)
}

// Inner is the privileged in-sandbox stage: chroot, rlimits, privdrop, exec.
// Invoked as: ctd __inner --root R [--cwd C] [--user U] [--rlimit k=v]... -- cmd...
func Inner(argv []string) int {
	root := "/"
	cwd := "/Users/me"
	user := "nobody"
	var uidOverride *int
	rlimits := map[string]uint64{}
	var cmd []string

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			cmd = argv[i+1:]
			i = len(argv)
		case a == "--root" && i+1 < len(argv):
			root = argv[i+1]
			i++
		case a == "--cwd" && i+1 < len(argv):
			cwd = argv[i+1]
			i++
		case a == "--user" && i+1 < len(argv):
			user = argv[i+1]
			i++
		case a == "--uid" && i+1 < len(argv):
			var u int
			if _, err := fmt.Sscanf(argv[i+1], "%d", &u); err == nil {
				uidOverride = &u
			}
			i++
		case a == "--rlimit" && i+1 < len(argv):
			kv := strings.SplitN(argv[i+1], "=", 2)
			if len(kv) == 2 {
				var v uint64
				if _, err := fmt.Sscanf(kv[1], "%d", &v); err == nil {
					rlimits[kv[0]] = v
				}
			}
			i++
		default:
			fmt.Fprintf(os.Stderr, "ctd __inner: unexpected arg %q\n", a)
			return 64
		}
	}
	if len(cmd) == 0 {
		fmt.Fprintln(os.Stderr, "ctd __inner: no command")
		return 64
	}

	// 1. chroot
	if err := syscall.Chroot(root); err != nil {
		fmt.Fprintf(os.Stderr, "ctd: chroot %s: %v\n", root, err)
		return 70
	}
	if err := os.Chdir(cwd); err != nil {
		if err := os.Chdir("/"); err != nil {
			fmt.Fprintf(os.Stderr, "ctd: chdir: %v\n", err)
			return 70
		}
	}

	// 2. rlimits (defaults from plan: cpu 600s, fsize 1GB, nproc 128, nofile 256)
	lim := map[string]uint64{"cpu": 600, "fsize": 1 << 30, "nproc": 128, "nofile": 256, "core": 0}
	for k, v := range rlimits {
		lim[k] = v
	}
	setLimit := func(res int, name string, v uint64) {
		if err := syscall.Setrlimit(res, &syscall.Rlimit{Cur: v, Max: v}); err != nil {
			fmt.Fprintf(os.Stderr, "ctd: rlimit %s: %v\n", name, err)
		}
	}
	setLimit(syscall.RLIMIT_CPU, "cpu", lim["cpu"])
	setLimit(syscall.RLIMIT_FSIZE, "fsize", lim["fsize"])
	setLimit(syscall.RLIMIT_NOFILE, "nofile", lim["nofile"])
	setLimit(syscall.RLIMIT_CORE, "core", lim["core"])
	// Darwin: no RLIMIT_NPROC; 7 is RLIMIT_NPROC on BSD — kernel rejects
	// unknown resources with EINVAL, which setLimit only warns about.
	const rlimitNPROC = 7
	if v, ok := lim["nproc"]; ok {
		setLimit(rlimitNPROC, "nproc", v)
	}

	// 3. privilege drop: template uid wins, then user: root, then nobody.
	uid, gid := -2, -2
	if user == "root" {
		uid, gid = 0, 0
	}
	if uidOverride != nil && *uidOverride != 0 {
		uid, gid = *uidOverride, *uidOverride
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		fmt.Fprintf(os.Stderr, "ctd: setgroups: %v\n", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		fmt.Fprintf(os.Stderr, "ctd: setgid: %v\n", err)
		return 77
	}
	if err := syscall.Setuid(uid); err != nil {
		fmt.Fprintf(os.Stderr, "ctd: setuid: %v\n", err)
		return 77
	}

	// 4. close stray fds (only 0/1/2 remain after Go's exec)
	_ = closeFrom(3)

	// 5. exec
	path := cmd[0]
	if !strings.Contains(path, "/") {
		if lp, err := exec.LookPath(path); err == nil {
			path = lp
		}
	}
	if err := syscall.Exec(path, cmd, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "ctd: exec %s: %v\n", path, err)
		return 127
	}
	return 0
}

func closeFrom(fd int) error {
	var e error
	for ; fd < 1024; fd++ {
		if err := syscall.Close(fd); err != nil {
			if e == nil {
				e = err
			}
		}
	}
	return nil
}
