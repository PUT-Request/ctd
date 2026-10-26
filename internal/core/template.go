package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// BootstrappingSpec installs third-party apps at create time: each command
// runs as root inside the container (writes confined to its own shadow),
// then new Mach-O files are re-signed plain ad-hoc and primed.
type BootstrappingSpec struct {
	Commands []string `json:"commands,omitempty" yaml:"commands,omitempty"`
	Network  *bool    `json:"network,omitempty" yaml:"network,omitempty"` // nil = follow the template
	Timeout  int      `json:"timeout,omitempty" yaml:"timeout,omitempty"` // seconds per command, default 300
}

// ShareSpec pairs a host path with a container path. Shares sync at exec
// boundaries: host→container before exec, container→host after exec (rw).
type ShareSpec struct {
	Host      string `json:"host" yaml:"host"`
	Container string `json:"container" yaml:"container"`
	Mode      string `json:"mode,omitempty" yaml:"mode,omitempty"` // rw (default) | ro
	// Overwrite=false keeps container-side files that differ from host
	// (needed for executables re-signed inside the container).
	Overwrite *bool `json:"overwrite,omitempty" yaml:"overwrite,omitempty"`
}

// Spec is a container template.
// YAML in, validated, persisted to meta.json, applied on every exec.
type Spec struct {
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	TTL  any    `json:"ttl,omitempty" yaml:"ttl,omitempty"` // int seconds | "4h" | "never"
	// normalized:
	TTLSeconds    int                `json:"ttl_seconds" yaml:"-"`
	User          string             `json:"user,omitempty" yaml:"user,omitempty"` // nobody (default) | root
	Workdir       string             `json:"workdir,omitempty" yaml:"workdir,omitempty"`
	Home          string             `json:"home,omitempty" yaml:"home,omitempty"` // private per-container home
	Shell         string             `json:"shell,omitempty" yaml:"shell,omitempty"`
	Env           map[string]string  `json:"env,omitempty" yaml:"env,omitempty"`
	Tools         []string           `json:"tools,omitempty" yaml:"tools,omitempty"`
	Resources     Resources          `json:"resources,omitempty" yaml:"resources,omitempty"`
	Writable      []string           `json:"writable,omitempty" yaml:"writable,omitempty"`
	Shares        []ShareSpec        `json:"shares,omitempty" yaml:"shares,omitempty"`
	Network       NetworkSpec        `json:"network,omitempty" yaml:"network,omitempty"`
	Firewall      *FirewallSpec      `json:"firewall,omitempty" yaml:"firewall,omitempty"`
	Bootstrapping *BootstrappingSpec `json:"bootstrapping,omitempty" yaml:"bootstrapping,omitempty"`
	// ShareProcessList=false (default): hides foreign processes from ps
	// and signals.
	ShareProcessList bool         `json:"share_process_list,omitempty" yaml:"share_process_list,omitempty"`
	Seatbelt         SeatbeltSpec `json:"seatbelt,omitempty" yaml:"seatbelt,omitempty"`
}

// Resources → setrlimit(2) applied in __inner before exec.
type Resources struct {
	CPUSeconds  *uint64 `json:"cpu_seconds,omitempty"  yaml:"cpu_seconds,omitempty"`
	FsizeBytes  *uint64 `json:"fsize_bytes,omitempty"  yaml:"fsize_bytes,omitempty"`
	Nproc       *uint64 `json:"nproc,omitempty"        yaml:"nproc,omitempty"`
	Nofile      *uint64 `json:"nofile,omitempty"       yaml:"nofile,omitempty"`
	MemoryBytes *uint64 `json:"memory_bytes,omitempty" yaml:"memory_bytes,omitempty"` // RLIMIT_AS
	Core        *uint64 `json:"core,omitempty"         yaml:"core,omitempty"`
	// DiskMaxBytes caps the container's disk footprint (admission gate
	// before every exec; 0 = unlimited).
	DiskMaxBytes *uint64 `json:"disk_max_bytes,omitempty" yaml:"disk_max_bytes,omitempty"`
}

// NetworkSpec gates all socket operations (Seatbelt default: deny).
type NetworkSpec struct {
	Allow bool `json:"allow" yaml:"allow"`
}

// SeatbeltSpec appends raw SBPL rules verbatim.
type SeatbeltSpec struct {
	ExtraRules string `json:"extra_rules,omitempty" yaml:"extra_rules,omitempty"`
}

// DefaultWritable is the write allow-list when the template omits it.
var DefaultWritable = []string{"/Users/me", "/private/tmp", "/private/var"}

// DefaultSpec returns the secure defaults: no network, minimal writes,
// private home, process list hidden, nobody.
func DefaultSpec() *Spec {
	s := &Spec{}
	_ = s.Normalize()
	return s
}

// ParseTemplate reads + validates a YAML template.
func ParseTemplate(path string) (*Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseTemplateBytes(b)
}

// ParseTemplateBytes parses YAML from memory (HTTP/RPC deploy too).
func ParseTemplateBytes(b []byte) (*Spec, error) {
	var s Spec
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if err := s.Normalize(); err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Normalize fills defaults and converts TTL into TTLSeconds.
func (s *Spec) Normalize() error {
	switch v := s.TTL.(type) {
	case nil:
	case int:
		s.TTLSeconds = v
	case int64:
		s.TTLSeconds = int(v)
	case uint64:
		s.TTLSeconds = int(v)
	case float64:
		s.TTLSeconds = int(v)
	case string:
		t := strings.TrimSpace(v)
		if t == "" || t == "never" || t == "0" {
			s.TTLSeconds = 0
		} else if n, err := strconv.Atoi(t); err == nil {
			s.TTLSeconds = n
		} else {
			d, err := time.ParseDuration(t)
			if err != nil {
				return fmt.Errorf("ttl %q: %w", v, err)
			}
			s.TTLSeconds = int(d.Seconds())
		}
	default:
		return fmt.Errorf("ttl: unsupported type %T", v)
	}
	s.TTL = nil

	if s.Workdir == "" {
		s.Workdir = "/Users/me"
	}
	if s.Home == "" {
		s.Home = "/Users/me" // each container gets its own private home by default
	}
	if s.User == "" {
		s.User = "nobody"
	}
	if s.Shell == "" {
		s.Shell = "/bin/bash"
	}
	if len(s.Writable) == 0 {
		s.Writable = append([]string{}, DefaultWritable...)
	}
	if s.Bootstrapping != nil && s.Bootstrapping.Timeout <= 0 {
		s.Bootstrapping.Timeout = 300
	}
	// Shares are writable by definition — fold their targets in.
	for _, sh := range s.Shares {
		if sh.Container != "" && !containsPath(s.Writable, sh.Container) {
			s.Writable = append(s.Writable, sh.Container)
		}
	}
	return nil
}

func containsPath(list []string, p string) bool {
	for _, x := range list {
		if x == p {
			return true
		}
	}
	return false
}

// Validate rejects templates that cannot work.
func (s *Spec) Validate() error {
	if s.TTLSeconds < 0 {
		return fmt.Errorf("ttl must be >= 0")
	}
	if s.User != "nobody" && s.User != "root" {
		return fmt.Errorf("user must be nobody or root, got %q", s.User)
	}
	for _, key := range []struct{ name, val string }{
		{"workdir", s.Workdir}, {"home", s.Home},
	} {
		if !strings.HasPrefix(key.val, "/") {
			return fmt.Errorf("%s must be absolute, got %q", key.name, key.val)
		}
	}
	for _, w := range s.Writable {
		if !strings.HasPrefix(w, "/") {
			return fmt.Errorf("writable paths must be absolute, got %q", w)
		}
	}
	// Tools must be in the curated re-signed set.
	curated := map[string]bool{}
	for _, t := range CuratedTools {
		curated[baseName(t)] = true
	}
	var missing []string
	for _, t := range s.Tools {
		if !curated[baseName(t)] {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("tools not in curated set — add to CuratedTools in internal/core/base.go and rerun `sudo ctd base prepare --force`: %s", strings.Join(missing, ", "))
	}
	for i, sh := range s.Shares {
		if sh.Host == "" || sh.Container == "" {
			return fmt.Errorf("shares[%d]: host and container are both required", i)
		}
		if !strings.HasPrefix(sh.Container, "/") {
			return fmt.Errorf("shares[%d].container must be absolute, got %q", i, sh.Container)
		}
		mode := sh.Mode
		if mode == "" {
			mode = "rw"
		}
		if mode != "rw" && mode != "ro" {
			return fmt.Errorf("shares[%d].mode must be rw or ro, got %q", i, sh.Mode)
		}
		if sh.Host == "" || sh.Container == "" {
			return fmt.Errorf("shares[%d]: host and container are both required", i)
		}
		if host := ExpandHostPath(sh.Host); host == "" {
			return fmt.Errorf("shares[%d].host empty after expansion", i)
		}
	}
	if s.Seatbelt.ExtraRules != "" && !strings.Contains(s.Seatbelt.ExtraRules, "(") {
		return fmt.Errorf("seatbelt.extra_rules does not look like SBPL")
	}
	if s.Firewall != nil {
		if s.Network.Allow {
			return fmt.Errorf("network.allow and firewall are mutually exclusive")
		}
		if err := s.Firewall.Validate(); err != nil {
			return err
		}
	}
	if s.Bootstrapping != nil {
		for i, c := range s.Bootstrapping.Commands {
			if strings.TrimSpace(c) == "" {
				return fmt.Errorf("bootstrapping.commands[%d] is empty", i)
			}
		}
	}
	return nil
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// ExpandHostPath resolves a leading ~ to the invoking (sudo) user's home.
func ExpandHostPath(p string) string {
	if p == "" {
		return ""
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		home := os.Getenv("HOME")
		if u := os.Getenv("SUDO_USER"); u != "" && u != "root" {
			if out, err := exec.Command("/bin/sh", "-c", "eval echo ~"+u).Output(); err == nil {
				home = strings.TrimSpace(string(out))
			}
		}
		return filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p
}

// Set applies a dotted override: network.allow=true, ttl=2h,
// env.FOO=bar, shares=/host:/container:rw (append), resources.cpu_seconds=600…
func (s *Spec) Set(kv string) error {
	eq := strings.Index(kv, "=")
	if eq < 0 {
		return fmt.Errorf("--set expects key=value, got %q", kv)
	}
	key, val := kv[:eq], kv[eq+1:]
	switch key {
	case "name":
		s.Name = val
	case "ttl":
		s.TTL = val
		if err := s.Normalize(); err != nil {
			return err
		}
	case "workdir":
		s.Workdir = val
	case "home":
		s.Home = val
	case "user":
		s.User = val
	case "shell":
		s.Shell = val
	case "network.allow":
		b, err := parseBool(val)
		if err != nil {
			return fmt.Errorf("network.allow: %w", err)
		}
		s.Network.Allow = b
	case "share_process_list":
		b, err := parseBool(val)
		if err != nil {
			return fmt.Errorf("share_process_list: %w", err)
		}
		s.ShareProcessList = b
	case "writable":
		s.Writable = strings.Split(val, ",")
	case "seatbelt.extra_rules":
		s.Seatbelt.ExtraRules = val
	case "firewall.allow_out":
		if s.Firewall == nil {
			s.Firewall = &FirewallSpec{}
		}
		s.Firewall.AllowOut = splitNonEmpty(val)
		if err := s.Firewall.Validate(); err != nil {
			return err
		}
	case "firewall.allow_in":
		if s.Firewall == nil {
			s.Firewall = &FirewallSpec{}
		}
		s.Firewall.AllowIn = splitNonEmpty(val)
		if err := s.Firewall.Validate(); err != nil {
			return err
		}
	case "firewall.dns":
		b, err := parseBool(val)
		if err != nil {
			return fmt.Errorf("firewall.dns: %w", err)
		}
		if s.Firewall == nil {
			s.Firewall = &FirewallSpec{}
		}
		s.Firewall.DNS = &b
	case "bootstrapping.command":
		if s.Bootstrapping == nil {
			s.Bootstrapping = &BootstrappingSpec{}
		}
		s.Bootstrapping.Commands = append(s.Bootstrapping.Commands, val)
	case "bootstrapping.network":
		b, err := parseBool(val)
		if err != nil {
			return fmt.Errorf("bootstrapping.network: %w", err)
		}
		if s.Bootstrapping == nil {
			s.Bootstrapping = &BootstrappingSpec{}
		}
		s.Bootstrapping.Network = &b
	case "bootstrapping.timeout":
		if s.Bootstrapping == nil {
			s.Bootstrapping = &BootstrappingSpec{}
		}
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 {
			return fmt.Errorf("bootstrapping.timeout: want seconds > 0")
		}
		s.Bootstrapping.Timeout = n
	case "share":
		// --set share=/host/dir:/container/dir:rw
		parts := strings.Split(val, ":")
		if len(parts) < 2 {
			return fmt.Errorf("share expects /host:/container[:rw|ro]")
		}
		sh := ShareSpec{Host: parts[0], Container: parts[1], Mode: "rw"}
		if len(parts) >= 3 && parts[2] != "" {
			sh.Mode = parts[2]
		}
		s.Shares = append(s.Shares, sh)
	case "env":
		s.Env = map[string]string{}
		for _, kv2 := range strings.Split(val, ",") {
			if k, v, ok := strings.Cut(kv2, "="); ok {
				s.Env[k] = v
			}
		}
	default:
		if strings.HasPrefix(key, "env.") {
			if s.Env == nil {
				s.Env = map[string]string{}
			}
			s.Env[strings.TrimPrefix(key, "env.")] = val
			break
		}
		if strings.HasPrefix(key, "resources.") {
			n, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
			switch strings.TrimPrefix(key, "resources.") {
			case "cpu_seconds":
				s.Resources.CPUSeconds = &n
			case "fsize_bytes":
				s.Resources.FsizeBytes = &n
			case "nproc":
				s.Resources.Nproc = &n
			case "nofile":
				s.Resources.Nofile = &n
			case "memory_bytes":
				s.Resources.MemoryBytes = &n
			case "disk_max_bytes":
				s.Resources.DiskMaxBytes = &n
			case "core":
				s.Resources.Core = &n
			default:
				return fmt.Errorf("unknown resource %q", key)
			}
			break
		}
		return fmt.Errorf("unknown --set key %q (supported: name, ttl, workdir, home, user, shell, network.allow, firewall.allow_out/allow_in/dns, bootstrapping.command/network/timeout, share_process_list, writable, share=/h:/c[:rw|ro], env[.KEY], resources.*, seatbelt.extra_rules)", key)
	}
	return s.Normalize()
}

func splitNonEmpty(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("want true/false, got %q", v)
}

// Rlimits converts resources to the k=v map consumed by __inner.
func (s *Spec) Rlimits() map[string]uint64 {
	m := map[string]uint64{}
	if s.Resources.CPUSeconds != nil {
		m["cpu"] = *s.Resources.CPUSeconds
	}
	if s.Resources.FsizeBytes != nil {
		m["fsize"] = *s.Resources.FsizeBytes
	}
	if s.Resources.Nproc != nil {
		m["nproc"] = *s.Resources.Nproc
	}
	if s.Resources.Nofile != nil {
		m["nofile"] = *s.Resources.Nofile
	}
	if s.Resources.MemoryBytes != nil {
		m["as"] = *s.Resources.MemoryBytes
	}
	if s.Resources.Core != nil {
		m["core"] = *s.Resources.Core
	}
	return m
}

// ExampleTemplate is emitted by `ctd template new`.
func ExampleTemplate() string {
	return `# ctd container template
#   validate:  ctd template validate this.yaml
#   deploy:    sudo ctd deploy -f this.yaml [--name mybox] [--set network.allow=true]
name: example
ttl: 4h                     # seconds | "4h" | "never"
user: nobody                # nobody (dedicated uid) | root
workdir: /Users/me          # cwd inside the container
home: /Users/me             # private per-container HOME (default)
shell: /bin/bash
env:
  APP_ENV: dev
tools:                      # must be in the curated re-signed set
  - curl
  - grep
resources:
  cpu_seconds: 1800
  fsize_bytes: 1073741824
  memory_bytes: 2147483648
  disk_max_bytes: 2147483648   # max disk footprint (0 = unlimited)
  nproc: 256
  nofile: 512
  core: 0
writable:                   # Seatbelt write allow-list (default below);
  - /Users/me               #   container system tree is read-only to it
  - /private/tmp
  - /private/var
shares:                     # host ↔ container path sharing (sync at exec
  - host: ~/src             #   boundaries — macOS has no bind mounts)
    container: /src
    mode: rw                # rw: synced back after exec | ro: in only
network:
  allow: false              # true = all sockets + DNS
firewall:                   # rule-based network (instead of network.allow)
  dns: true                 # name resolution via the resolver bridge
  allow_out:                # outbound, default deny
    - tcp:443
    - tcp:22
  allow_in:                 # bind/listen, default deny
    - tcp:8080
bootstrapping:              # install third-party apps at create time
  commands:
    - "curl -fsSL https://example.com/tool.tar.gz | tar xz -C /Users/me/.local"
  network: false            # temporary network during bootstrap only
  timeout: 300
share_process_list: false   # ps can't see host/other containers
seatbelt:
  extra_rules: ""           # raw SBPL appended verbatim
`
}
