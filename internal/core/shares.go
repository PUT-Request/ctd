package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// SyncShares copies declared shares at exec boundaries:
// host → container before exec, container → host after exec (rw only).
func SyncShares(root string, spec *Spec, uid int, direction string) error {
	if spec == nil || len(spec.Shares) == 0 {
		return nil
	}
	var errs []string
	for _, sh := range spec.Shares {
		mode := sh.Mode
		if mode == "" {
			mode = "rw"
		}
		switch direction {
		case "in":
			host := ExpandHostPath(sh.Host)
			if fi, err := os.Stat(host); err != nil || !fi.IsDir() {
				errs = append(errs, fmt.Sprintf("%s: host dir %q not found", sh.Host, host))
				continue
			}
			dst := filepath.Join(root, sh.Container)
			if err := os.MkdirAll(dst, 0o755); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", sh.Container, err))
				continue
			}
			// trailing slash = copy contents
			args := []string{"-a", "--safe-links"}
			if sh.Overwrite != nil && !*sh.Overwrite {
				args = append(args, "--ignore-existing")
			}
			args = append(args, host+string(os.PathSeparator), dst+string(os.PathSeparator))
			if err := rsyncArgs(args...); err != nil {
				errs = append(errs, fmt.Sprintf("in %s: %v", sh.Host, err))
				continue
			}
			// the container must own its share copy (its uid ≠ root)
			_ = RunOK("/usr/sbin/chown", "-R", strconv.Itoa(uid), dst)
		case "out":
			if mode != "rw" {
				continue // ro shares never write back
			}
			host := ExpandHostPath(sh.Host)
			src := filepath.Join(root, sh.Container)
			if fi, err := os.Stat(src); err != nil || !fi.IsDir() {
				continue
			}
			// sync back AS THE INVOKING USER: root never rewrites ownership
			// or modes in the user's home directory.
			uidStr, gidStr := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
			u, e1 := strconv.Atoi(uidStr)
			g, e2 := strconv.Atoi(gidStr)
			if uidStr == "" || e1 != nil || e2 != nil {
				errs = append(errs, fmt.Sprintf("out %s: skipped — run ctd via sudo so the sync runs as your user (root will not write your home)", sh.Host))
				continue
			}
			if err := rsyncAsUser(uint32(u), uint32(g),
				src+string(os.PathSeparator), host+string(os.PathSeparator)); err != nil {
				errs = append(errs, fmt.Sprintf("out %s: %v", sh.Host, err))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// rsync invokes macOS's bundled rsync.
func rsync(src, dst string) error {
	return rsyncArgs("-a", "--safe-links", src, dst)
}

// rsyncAsUser syncs container → host with the given credentials; as a
// non-root user rsync cannot alter ownership of existing host files and
// creates new ones owned by that user.
func rsyncAsUser(uid, gid uint32, src, dst string) error {
	cmd := exec.Command("/usr/bin/rsync", "-a", src, dst)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid},
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rsync: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func rsyncArgs(args ...string) error {
	out, err := exec.Command("/usr/bin/rsync", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rsync: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// signShareExes signs share-provided executables that are unsigned or were
// overwritten by a host sync; returns the newly signed paths.
func signShareExes(name, root string, spec *Spec) []string {
	var signed []string
	for _, sh := range spec.Shares {
		base := filepath.Join(root, sh.Container)
		_ = filepath.Walk(base, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
				return nil
			}
			if !isMachO(p) || strings.HasSuffix(p, ".dylib") {
				return nil
			}
			out, derr := Run("codesign", "-d", p)
			ident := ""
			if derr == nil {
				for _, line := range strings.Split(out, "\n") {
					if v, ok := strings.CutPrefix(line, "Identifier="); ok {
						ident = v
						break
					}
				}
			}
			if derr != nil || !strings.HasPrefix(ident, "ctd-") {
				rel, _ := filepath.Rel(base, p)
				slug := strings.NewReplacer("/", "-").Replace(strings.TrimPrefix(sh.Container+rel, "/"))
				if rserr := RunOK("codesign", "-s", "-", "--force",
					"--identifier", "ctd-"+name+"-"+slug, p); rserr == nil {
					signed = append(signed, p)
				}
			}
			return nil
		})
	}
	return signed
}
