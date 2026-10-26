package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Container is the host-side view of a container.
type Container struct {
	Name           string     `json:"name"`
	CreatedAt      time.Time  `json:"created_at"`
	TTLSeconds     int        `json:"ttl_seconds"`
	DMG            string     `json:"dmg"`
	Uid            int        `json:"uid"`
	Network        bool       `json:"network_enabled"`
	BootstrappedAt *time.Time `json:"bootstrapped_at,omitempty"`
	Root           string     `json:"root"`
	Shadow         string     `json:"shadow"`
	Attached       bool       `json:"attached"`
	Expired        bool       `json:"expired"`
	ShadowSize     int64      `json:"shadow_size"`
	ShadowUsed     int64      `json:"shadow_used"`
}

type meta struct {
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	TTLSeconds int       `json:"ttl_seconds"`
	DMG        string    `json:"dmg"`
	// Uid is the dedicated per-container uid (0 = legacy nobody/-2).
	Uid int `json:"uid,omitempty"`
	// Spec is the deployed template (nil = legacy, use DefaultSpec).
	Spec *Spec `json:"spec,omitempty"`
	// BootstrappedAt records a successful bootstrapping run.
	BootstrappedAt *time.Time `json:"bootstrapped_at,omitempty"`
}

// effectiveSpec returns the stored spec or secure defaults.
func (m *meta) effectiveSpec() *Spec {
	if m.Spec == nil {
		return DefaultSpec()
	}
	return m.Spec
}

// effectiveUid returns the container uid (legacy containers: nobody -2).
func (m *meta) effectiveUid() int {
	if m.Uid == 0 {
		return -2
	}
	return m.Uid
}

// nextUid allocates a dedicated uid from the 60000 range.
func nextUid() (int, error) {
	used := map[int]bool{}
	entries, err := os.ReadDir(ContainersDir)
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if m, err := LoadMeta(e.Name()); err == nil && m.Uid != 0 {
			used[m.Uid] = true
		}
	}
	for u := 60001; u < 65535; u++ {
		if !used[u] {
			return u, nil
		}
	}
	return 0, fmt.Errorf("uid space exhausted")
}

// Dir returns the container directory.
func Dir(name string) string { return filepath.Join(ContainersDir, name) }

// Root returns the chroot root for a container (plain dir on Data).
func Root(name string) string { return filepath.Join(Dir(name), "root") }

// imgShadow returns the per-container CoW shadow for the ro image mount.
func imgShadow(name string) string { return filepath.Join(Dir(name), "img.shadow") }

// shadow is kept for display: the only shadow a thin container has.
func shadow(name string) string { return imgShadow(name) }

func expiresAt(m *meta) time.Time {
	if m.TTLSeconds <= 0 {
		return time.Time{}
	}
	return m.CreatedAt.Add(time.Duration(m.TTLSeconds) * time.Second)
}

// LoadMeta reads a container's metadata.
func LoadMeta(name string) (*meta, error) {
	b, err := os.ReadFile(filepath.Join(Dir(name), "meta.json"))
	if err != nil {
		return nil, err
	}
	var m meta
	if err := jsonUnmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func writeMeta(m *meta) error {
	b, err := jsonMarshalIndent(m)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(Dir(m.Name), "meta.json"), b, 0o644)
}

// Create builds a thin container: cp -c the base tree (shares blocks until
// written), mount the dmg read-only at <root>/img, mount devfs, prime, then
// materialize shares and run bootstrapping.
func Create(name string, spec *Spec) (*Container, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	if spec == nil {
		spec = DefaultSpec()
	}
	if err := spec.Normalize(); err != nil {
		return nil, err
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	spec.Name = name
	man, err := LoadManifest()
	if err != nil {
		return nil, err
	}
	dir := Dir(name)
	if _, err := os.Stat(dir); err == nil {
		return nil, fmt.Errorf("container %q already exists", name)
	}
	if err := EnsureDir(dir, 0o755); err != nil {
		return nil, err
	}

	attachMu.Lock()
	// APFS clone of the base tree on the Data volume (shares blocks until written)
	if out, err := Run("/bin/cp", "-R", "-c", "-p", BaseRoot, Root(name)); err != nil {
		attachMu.Unlock()
		return nil, fmt.Errorf("clone base tree: %v: %s", err, strings.TrimSpace(out))
	}
	// unique identifier → fresh cdhash per container: provenance records
	// key on (path × cdhash); a recreated name must not inherit old ones.
	for _, t := range CuratedTools {
		dst := filepath.Join(Root(name), t)
		if _, err := os.Stat(dst); err != nil {
			continue
		}
		ident := "ctd-" + name + "-" + strings.ReplaceAll(strings.TrimPrefix(t, "/"), "/", "-")
		_ = RunOK("codesign", "-s", "-", "--force", "--identifier", ident, dst)
	}
	if err := attachLocked(name, man.DMG); err != nil {
		attachMu.Unlock()
		return nil, err
	}
	ensurePrimed(name)
	attachMu.Unlock()

	uid := 0
	if spec.User == "nobody" {
		if uid, err = nextUid(); err != nil {
			_ = Destroy(name)
			return nil, err
		}
	}
	// shares materialize at deploy (install semantics)
	if serr := SyncShares(Root(name), spec, uid, "in"); serr != nil {
		_ = Destroy(name)
		return nil, fmt.Errorf("share sync: %w", serr)
	}
	if signed := signShareExes(name, Root(name), spec); len(signed) > 0 {
		primePaths(filepath.Join(Root(name), "private/tmp"), signed...)
	}
	m := &meta{
		Name:       name,
		CreatedAt:  time.Now().UTC(),
		TTLSeconds: spec.TTLSeconds,
		DMG:        man.DMG,
		Uid:        uid,
		Spec:       spec,
	}
	// bootstrapping runs at create; failure removes the container
	if spec.Bootstrapping != nil && len(spec.Bootstrapping.Commands) > 0 {
		if _, berr := ExecuteBootstrap(name, spec); berr != nil {
			_ = Destroy(name)
			return nil, fmt.Errorf("bootstrap failed, container removed: %w", berr)
		}
		now := time.Now().UTC()
		m.BootstrappedAt = &now
	}
	if err := writeMeta(m); err != nil {
		return nil, err
	}
	return describe(m)
}

// attachLocked mounts the dmg read-only at <root>/img (own shadow → own
// volume instance) and devfs at <root>/dev. Caller holds attachMu.
func attachLocked(name, dmg string) error {
	root := Root(name)
	if Mounted(filepath.Join(root, "img")) {
		return nil
	}
	if err := EnsureDir(filepath.Join(root, "img"), 0o755); err != nil {
		return err
	}
	if out, err := Run("hdiutil", "attach", "-shadow", imgShadow(name),
		"-mountpoint", filepath.Join(root, "img"), dmg); err != nil {
		return fmt.Errorf("hdiutil attach: %v: %s", err, strings.TrimSpace(out))
	}
	if !Mounted(filepath.Join(root, "dev")) {
		if err := RunOK("mount", "-t", "devfs", "devfs", filepath.Join(root, "dev")); err != nil {
			_ = RunOK("hdiutil", "detach", filepath.Join(root, "img"))
			return fmt.Errorf("mount devfs: %w", err)
		}
	}
	return nil
}

// Attach ensures a container is mounted (e.g. after reboot).
func Attach(name string) error {
	m, err := LoadMeta(name)
	if err != nil {
		return err
	}
	attachMu.Lock()
	defer attachMu.Unlock()
	dmg := m.DMG
	if _, err := os.Stat(dmg); err != nil {
		if dmg, err = FindDMG(); err != nil {
			return err
		}
		m.DMG = dmg
		if serr := writeMeta(m); serr != nil {
			return serr
		}
	}
	if err := attachLocked(name, dmg); err != nil {
		return err
	}
	ensurePrimed(name)
	return nil
}

// Detach unmounts devfs and the image mount.
func Detach(name string) error {
	attachMu.Lock()
	defer attachMu.Unlock()
	return detachLocked(name)
}

// detachLocked unmounts devfs, then the image, then any legacy root mount.
// Caller holds attachMu.
func detachLocked(name string) error {
	root := Root(name)
	var firstErr error
	if Mounted(filepath.Join(root, "dev")) {
		if err := RunOK("umount", filepath.Join(root, "dev")); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if Mounted(filepath.Join(root, "img")) {
		if out, err := Run("hdiutil", "detach", filepath.Join(root, "img")); err != nil {
			time.Sleep(300 * time.Millisecond)
			if out2, err2 := Run("hdiutil", "detach", "-force", filepath.Join(root, "img")); err2 != nil && firstErr == nil {
				firstErr = fmt.Errorf("detach: %v: %s (retry: %v: %s)", err, strings.TrimSpace(out), err2, strings.TrimSpace(out2))
			}
		}
	}
	// legacy image-root containers (root itself is the mount)
	if Mounted(root) {
		if out, err := Run("hdiutil", "detach", root); err != nil {
			time.Sleep(300 * time.Millisecond)
			if _, err2 := Run("hdiutil", "detach", "-force", root); err2 != nil && firstErr == nil {
				firstErr = fmt.Errorf("detach: %v: %s", err, strings.TrimSpace(out))
			}
		}
	}
	return firstErr
}

// Destroy detaches and removes the container directory.
func Destroy(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if _, err := os.Stat(Dir(name)); err != nil {
		return fmt.Errorf("container %q not found", name)
	}
	if err := Detach(name); err != nil {
		return err
	}
	if err := os.RemoveAll(Dir(name)); err != nil {
		return fmt.Errorf("remove container dir: %w", err)
	}
	return nil
}

// Describe returns the current state of a container.
func Describe(name string) (*Container, error) {
	m, err := LoadMeta(name)
	if err != nil {
		return nil, err
	}
	return describe(m)
}

func describe(m *meta) (*Container, error) {
	c := &Container{
		Name:           m.Name,
		CreatedAt:      m.CreatedAt,
		TTLSeconds:     m.TTLSeconds,
		DMG:            m.DMG,
		Uid:            m.effectiveUid(),
		Network:        m.effectiveSpec().Network.Allow,
		BootstrappedAt: m.BootstrappedAt,
		Root:           Root(m.Name),
		Shadow:         shadow(m.Name),
		Attached:       Mounted(filepath.Join(Root(m.Name), "img")),
	}
	if exp := expiresAt(m); !exp.IsZero() {
		if time.Now().After(exp) {
			c.Expired = true
		}
	}
	if fi, err := os.Stat(c.Shadow); err == nil {
		c.ShadowSize = fi.Size()
		c.ShadowUsed = FileAllocated(c.Shadow)
	}
	return c, nil
}

// List returns all containers.
func List() ([]*Container, error) {
	entries, err := os.ReadDir(ContainersDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Container
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		c, err := Describe(e.Name())
		if err != nil {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

// GC destroys expired containers; returns names destroyed.
func GC() ([]string, error) {
	all, err := List()
	if err != nil {
		return nil, err
	}
	var destroyed []string
	for _, c := range all {
		if c.Expired {
			if err := Destroy(c.Name); err == nil {
				destroyed = append(destroyed, c.Name)
			}
		}
	}
	return destroyed, nil
}

// OnceResult is the outcome of a one-shot command.
type OnceResult struct {
	Container string      `json:"container"`
	Created   bool        `json:"created"`
	Destroyed bool        `json:"destroyed"`
	Result    *ExecResult `json:"result"`
}

// Once runs a single command with one-shot lifecycle: create from the
// template when missing, exec, destroy when rm is set.
func Once(name, templateFile string, argv []string, opts ExecOptions, rm bool) (*OnceResult, error) {
	out := &OnceResult{Container: name}
	if _, err := Describe(name); err != nil {
		if templateFile == "" {
			return nil, fmt.Errorf("container %q not found (deploy it or pass a template with -f)", name)
		}
		spec, perr := ParseTemplate(templateFile)
		if perr != nil {
			return nil, perr
		}
		if _, cerr := Create(name, spec); cerr != nil {
			return nil, cerr
		}
		out.Created = true
	}
	if rm {
		defer func() {
			if derr := Destroy(name); derr == nil {
				out.Destroyed = true
			}
		}()
	}
	res, err := Exec("once", name, argv, opts)
	out.Result = res
	return out, err
}

// Bootstrap re-runs a template's bootstrapping on an existing container.
func Bootstrap(name string) (int, error) {
	m, err := LoadMeta(name)
	if err != nil {
		return 0, err
	}
	spec := m.effectiveSpec()
	if spec.Bootstrapping == nil || len(spec.Bootstrapping.Commands) == 0 {
		return 0, fmt.Errorf("container %q has no bootstrapping.commands", name)
	}
	if err := Attach(name); err != nil {
		return 0, err
	}
	n, err := ExecuteBootstrap(name, spec)
	if err == nil {
		now := time.Now().UTC()
		m.BootstrappedAt = &now
		if werr := writeMeta(m); werr != nil {
			return n, werr
		}
	}
	return n, err
}
