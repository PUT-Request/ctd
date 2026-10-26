package core

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Paths — all container state lives under OptDir (Data volume).
const (
	OptDir        = "/opt/ctd"
	BaseDir       = "/opt/ctd/base"
	BaseShadow    = "/opt/ctd/base/base.shadow"
	BaseMnt       = "/opt/ctd/base/mnt"
	BaseManifest  = "/opt/ctd/base/manifest.json"
	ContainersDir = "/opt/ctd/containers"
	LogsDir       = "/opt/ctd/logs"
	AuditLog      = "/opt/ctd/logs/audit.jsonl"
	RecoveryMnt   = "/opt/ctd/recovery"
	BinPath       = "/opt/ctd/bin/ctd"
)

// Serializes attach/detach operations (hdiutil races otherwise).
var attachMu sync.Mutex

// Run executes a command and returns combined output.
func Run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// RunOK executes a command and returns an error with output on failure.
func RunOK(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Mounted reports whether path is an active mountpoint (checked against `mount`).
func Mounted(path string) bool {
	out, _ := exec.Command("mount").CombinedOutput()
	marker := " on " + path + " ("
	return strings.Contains(string(out), marker)
}

// MountPoints returns all current mountpoints.
func MountPoints() []string {
	out, _ := exec.Command("mount").CombinedOutput()
	var pts []string
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, " on "); i >= 0 {
			rest := line[i+4:]
			if j := strings.Index(rest, " ("); j >= 0 {
				pts = append(pts, rest[:j])
			}
		}
	}
	return pts
}

// HumanBytes formats byte counts.
func HumanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// FileAllocated returns physical bytes allocated for a file (APFS blocks).
func FileAllocated(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fi.Size()
	}
	return st.Blocks * 512
}

// Audit appends a JSON line to the audit log.
func Audit(source, container string, cmd []string, exitCode int, dur time.Duration, extra map[string]any) {
	f, err := os.OpenFile(AuditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	rec := map[string]any{
		"ts":        time.Now().UTC().Format(time.RFC3339),
		"source":    source,
		"container": container,
		"cmd":       cmd,
		"exit":      exitCode,
		"duration":  dur.Milliseconds(),
	}
	for k, v := range extra {
		rec[k] = v
	}
	b, _ := json.Marshal(rec)
	f.Write(append(b, '\n'))
}

// ValidateName enforces safe container names.
func ValidateName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("name must be 1-64 chars")
	}
	for _, c := range name {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return fmt.Errorf("invalid character %q in name", c)
		}
	}
	return nil
}

// SanitizeEnv builds a clean environment for container processes.
func SanitizeEnv(home, cwd string, extra map[string]string) []string {
	env := map[string]string{
		"PATH":    "/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME":    home,
		"TMPDIR":  "/private/tmp",
		"USER":    "nobody",
		"LOGNAME": "nobody",
		"SHELL":   "/bin/bash",
	}
	if term := os.Getenv("TERM"); term != "" {
		env["TERM"] = term
	}
	for k, v := range extra {
		env[k] = v
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

// EnsureDir creates a directory with parents.
func EnsureDir(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// RelTime returns a human duration since t.
func RelTime(t time.Time) string {
	d := time.Since(t).Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}
