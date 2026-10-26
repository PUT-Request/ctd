package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BaseRoot is the thin-root base: a real directory tree on the Data
// volume (re-signed tools + skeleton + symlinks into <root>/img where
// the read-only Recovery dmg is mounted per container).
const BaseRoot = "/opt/ctd/base/root"

// Staging is the temporary read-only mount of the Recovery dmg used to
// source tools while building the base.
const (
	Staging       = "/opt/ctd/base/staging"
	stagingShadow = "/opt/ctd/base/staging.shadow"
)

// Manifest describes a prepared base.
type Manifest struct {
	CreatedAt time.Time `json:"created_at"`
	DMG       string    `json:"dmg"`
	// ToolsSigned are the curated tools present and re-signed in the tree.
	ToolsSigned []string `json:"tools_signed"`
	// ToolsMissing are CuratedTools absent from the Recovery image.
	ToolsMissing []string `json:"tools_missing"`
	// TreeBytes is the logical size of the base tree.
	TreeBytes int64 `json:"tree_bytes"`
	Version   int   `json:"version"`
}

// CuratedTools are re-signed plain ad-hoc for in-container exec.
// Missing tools are skipped.
var CuratedTools = []string{
	"/bin/sh", "/bin/bash", "/bin/zsh", "/bin/ls", "/bin/cat", "/bin/cp", "/bin/mv",
	"/bin/rm", "/bin/mkdir", "/bin/chmod", "/bin/date", "/bin/df", "/bin/ps",
	"/bin/sleep", "/bin/ln", "/bin/dd", "/bin/echo", "/bin/pwd", "/bin/stty",
	"/usr/bin/grep", "/usr/bin/sed", "/usr/bin/wc", "/usr/bin/head", "/usr/bin/tail",
	"/usr/bin/env", "/usr/bin/id", "/usr/bin/uname", "/usr/bin/awk", "/usr/bin/cut",
	"/usr/bin/sort", "/usr/bin/uniq", "/usr/bin/tr", "/usr/bin/seq", "/usr/bin/tee",
	"/usr/bin/xargs", "/usr/bin/find", "/usr/bin/touch", "/usr/bin/stat",
	"/usr/bin/yes", "/usr/bin/printf", "/usr/bin/dirname", "/usr/bin/basename",
	"/usr/bin/mktemp", "/usr/bin/curl", "/usr/bin/ssh", "/usr/bin/scp",
	"/usr/bin/tar", "/usr/bin/gzip", "/usr/bin/gunzip", "/usr/bin/kill",
	"/usr/bin/which", "/usr/bin/true", "/usr/bin/false", "/usr/bin/expr",
	"/usr/bin/bc", "/usr/bin/md5", "/usr/bin/sha256sum", "/usr/bin/tput",
	"/usr/bin/script", "/usr/bin/logger", "/usr/bin/last", "/usr/bin/w",
	"/usr/bin/uptime", "/usr/bin/systat", "/usr/bin/top", "/usr/bin/vi",
	"/usr/bin/nano", "/usr/bin/ruby", "/usr/bin/perl",
}

// FindRecoveryDevice locates the APFS Recovery volume device identifier.
func FindRecoveryDevice() (string, error) {
	out, err := Run("diskutil", "apfs", "list")
	if err != nil {
		return "", fmt.Errorf("diskutil apfs list: %v", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "(Recovery)") {
			for _, f := range strings.Fields(line) {
				if strings.HasPrefix(f, "disk") && strings.Contains(f, "s") {
					return f, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no Recovery volume found")
}

// RecoveryMountPoint returns where Recovery is mounted (mounting it ro if needed).
func RecoveryMountPoint() (string, error) {
	dev, err := FindRecoveryDevice()
	if err != nil {
		return "", err
	}
	marker := "/dev/" + dev + " on "
	for _, line := range strings.Split(mustMount(), "\n") {
		if strings.HasPrefix(line, marker) && strings.Contains(line, " (") {
			rest := line[len(marker):]
			return rest[:strings.Index(rest, " (")], nil
		}
	}
	if err := EnsureDir(RecoveryMnt, 0o755); err != nil {
		return "", err
	}
	if err := RunOK("mount", "-t", "apfs", "-o", "ro", "/dev/"+dev, RecoveryMnt); err != nil {
		return "", err
	}
	return RecoveryMnt, nil
}

func mustMount() string {
	out, _ := runMount()
	return out
}

func runMount() (string, error) {
	return Run("mount")
}

// FindDMG locates the RecoveryOS disk image (dyld cache + system trees).
func FindDMG() (string, error) {
	mp, err := RecoveryMountPoint()
	if err != nil {
		return "", err
	}
	var found []string
	_ = filepath.WalkDir(mp, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		depth := strings.Count(strings.TrimPrefix(path, mp), "/")
		if depth > 8 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			name := d.Name()
			if strings.HasSuffix(name, ".dmg") && (strings.Contains(name, "BaseSystem") || strings.Contains(name, "RecoveryOS")) {
				found = append(found, path)
			}
		}
		return nil
	})
	if len(found) == 0 {
		return "", fmt.Errorf("no BaseSystem dmg under %s", mp)
	}
	sort.Slice(found, func(i, j int) bool {
		di, dj := strings.Count(found[i], "/"), strings.Count(found[j], "/")
		if di != dj {
			return di < dj
		}
		return found[i] < found[j]
	})
	return found[0], nil
}

func isMachO(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.ReadAt(magic[:], 0); err != nil {
		return false
	}
	switch {
	case magic[0] == 0xcf && magic[1] == 0xfa,
		magic[0] == 0xce && magic[1] == 0xfa,
		magic[0] == 0xca && magic[1] == 0xfe:
		return true
	}
	return false
}

// PrepareBase builds (or rebuilds) the thin-root base tree. Idempotent.
func PrepareBase(force bool) (*Manifest, error) {
	if !force {
		if m, err := LoadManifest(); err == nil {
			return m, nil
		}
	}
	if err := EnsureDir(BaseDir, 0o755); err != nil {
		return nil, err
	}
	dmg, err := FindDMG()
	if err != nil {
		return nil, err
	}

	attachMu.Lock()
	defer attachMu.Unlock()

	// legacy cleanup: old image-shadow base
	_ = RunOK("/bin/rm", "-f", BaseShadow)
	if Mounted(Staging) {
		_ = RunOK("hdiutil", "detach", Staging)
	}
	if err := EnsureDir(Staging, 0o755); err != nil {
		return nil, err
	}
	if out, err := Run("hdiutil", "attach", "-shadow", stagingShadow, "-mountpoint", Staging, dmg); err != nil {
		return nil, fmt.Errorf("hdiutil attach: %v: %s", err, strings.TrimSpace(out))
	}
	defer func() {
		_ = RunOK("hdiutil", "detach", Staging)
		_ = RunOK("/bin/rm", "-f", stagingShadow)
	}()

	// fresh tree (legacy base removed)
	_ = RunOK("/bin/rm", "-rf", BaseRoot)
	skeleton := []string{
		"bin", "sbin", "usr/bin", "dev", "img", "private/etc", "private/var",
		"private/tmp", "Users/me", "opt", "Library", "cores", "Volumes",
		"Applications", "pkg", "home",
	}
	for _, d := range skeleton {
		if err := os.MkdirAll(filepath.Join(BaseRoot, d), 0o755); err != nil {
			return nil, err
		}
	}
	// symlinks: big trees come from the per-container ro image mount at <root>/img
	links := map[string]string{
		"usr/lib":     "../img/usr/lib",
		"usr/share":   "../img/usr/share",
		"usr/libexec": "../img/usr/libexec",
		"System":      "img/System",
		"etc":         "private/etc",
		"tmp":         "private/tmp",
		"var":         "private/var",
	}
	for name, target := range links {
		p := filepath.Join(BaseRoot, name)
		_ = os.RemoveAll(p)
		if err := os.Symlink(target, p); err != nil {
			return nil, fmt.Errorf("symlink %s: %w", name, err)
		}
	}

	// copy curated tools from the image → tree, re-sign there
	var signed, missing []string
	for _, t := range CuratedTools {
		src := filepath.Join(Staging, t)
		if _, err := os.Stat(src); err != nil || !isMachO(src) {
			missing = append(missing, t)
			continue
		}
		dst := filepath.Join(BaseRoot, t)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, err
		}
		if out, err := Run("/bin/cp", src, dst); err != nil {
			return nil, fmt.Errorf("copy %s: %v: %s", t, err, strings.TrimSpace(out))
		}
		if err := RunOK("codesign", "-s", "-", "--force", dst); err != nil {
			return nil, fmt.Errorf("codesign %s: %w", t, err)
		}
		signed = append(signed, t)
	}

	// /etc + accounts
	etc := filepath.Join(BaseRoot, "private/etc")
	files := map[string]string{
		"passwd": "root:*:0:0:System Administrator:/var/root:/bin/sh\n" +
			"nobody:*:-2:-2:Unprivileged User:/Users/me:/bin/sh\n" +
			"me:*:501:20:Container User:/Users/me:/bin/bash\n",
		"group":    "wheel:*:0:\nstaff:*:20:\nnogroup:*:-2:\n",
		"hosts":    "127.0.0.1\tlocalhost\n::1\t\tlocalhost\n",
		"hostname": "ctd-container\n",
		"issue":    "ctd macOS shell container\n",
	}
	if host, err := os.ReadFile("/etc/resolv.conf"); err == nil && len(host) > 0 {
		files["resolv.conf"] = string(host)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(etc, name), []byte(content), 0o644); err != nil {
			return nil, err
		}
	}
	// TLS trust
	if _, err := os.Stat("/private/etc/ssl/cert.pem"); err == nil {
		dst := filepath.Join(etc, "ssl")
		_ = os.MkdirAll(dst, 0o755)
		_, _ = Run("/bin/cp", "-R", "/private/etc/ssl/.", dst+"/")
	}
	_ = os.Chmod(filepath.Join(BaseRoot, "private/tmp"), 0o1777)
	_ = os.Chmod(filepath.Join(BaseRoot, "Users/me"), 0o777)
	_ = os.Chmod(filepath.Join(BaseRoot, "private/var"), 0o777)

	m := &Manifest{
		CreatedAt:    time.Now().UTC(),
		DMG:          dmg,
		ToolsSigned:  signed,
		ToolsMissing: missing,
		TreeBytes:    treeSize(BaseRoot),
		Version:      2,
	}
	if err := SaveManifest(m); err != nil {
		return nil, err
	}
	return m, nil
}

// treeSize sums regular-file bytes under root.
func treeSize(root string) int64 {
	var total int64
	_ = filepath.Walk(root, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			total += fi.Size()
		}
		return nil
	})
	return total
}

// LoadManifest reads the base manifest.
func LoadManifest() (*Manifest, error) {
	b, err := os.ReadFile(BaseManifest)
	if err != nil {
		return nil, fmt.Errorf("base not prepared: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if fi, err := os.Stat(BaseRoot); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("base not prepared: %s missing", BaseRoot)
	}
	// recorded path can vanish across reboots (tmp cleanup) → re-resolve
	if _, err := os.Stat(m.DMG); err != nil {
		dmg, derr := FindDMG()
		if derr != nil {
			return nil, derr
		}
		m.DMG = dmg
		if serr := SaveManifest(&m); serr != nil {
			return nil, serr
		}
	}
	return &m, nil
}

// SaveManifest writes the base manifest.
func SaveManifest(m *Manifest) error {
	if err := EnsureDir(BaseDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(BaseManifest, b, 0o644)
}
