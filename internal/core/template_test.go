package core

import "testing"

func TestTTLNormalizes(t *testing.T) {
	cases := map[string]int{"4h": 14400, "30m": 1800, "3600": 3600, "never": 0, "0": 0}
	for in, want := range cases {
		var s Spec
		s.TTL = in
		if err := s.Normalize(); err != nil {
			t.Fatalf("ttl %q: %v", in, err)
		}
		if s.TTLSeconds != want {
			t.Errorf("ttl %q → %d, want %d", in, s.TTLSeconds, want)
		}
	}
}

func TestDefaults(t *testing.T) {
	s := DefaultSpec()
	if s.Home != "/Users/me" || s.Workdir != "/Users/me" {
		t.Errorf("own home/workdir default broken: home=%q workdir=%q", s.Home, s.Workdir)
	}
	if s.User != "nobody" {
		t.Errorf("default user = %q, want nobody", s.User)
	}
	if s.Network.Allow {
		t.Error("network must be denied by default")
	}
	if s.ShareProcessList {
		t.Error("process list must be hidden by default")
	}
	if len(s.Writable) != len(DefaultWritable) {
		t.Errorf("default writable = %v", s.Writable)
	}
}

func TestValidateRejectsBadTemplates(t *testing.T) {
	bad := []struct {
		name string
		yaml string
	}{
		{"uncurated tool", "tools: [totally-not-curated]"},
		{"bad user", "user: superuser"},
		{"relative workdir", "workdir: relative/path"},
		{"bad share mode", "shares:\n  - host: /a\n    container: /b\n    mode: rw-rw"},
		{"relative share container", "shares:\n  - host: /a\n    container: rel/path"},
		{"missing share host", "shares:\n  - container: /b"},
	}
	for _, c := range bad {
		if _, err := ParseTemplateBytes([]byte(c.yaml)); err == nil {
			t.Errorf("%s: expected validation error, got nil", c.name)
		}
	}
}

func TestValidTemplateParses(t *testing.T) {
	yaml := `
name: box
ttl: 4h
user: nobody
network:
  allow: true
resources:
  cpu_seconds: 600
shares:
  - host: /tmp/src
    container: /src
    mode: rw
`
	s, err := ParseTemplateBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("valid template rejected: %v", err)
	}
	if s.Name != "box" || s.TTLSeconds != 14400 || !s.Network.Allow {
		t.Errorf("parsed wrong: %+v", s)
	}
	if s.Resources.CPUSeconds == nil || *s.Resources.CPUSeconds != 600 {
		t.Errorf("resources.cpu_seconds not parsed: %v", s.Resources)
	}
	// share target must be folded into the write allow-list
	found := false
	for _, w := range s.Writable {
		if w == "/src" {
			found = true
		}
	}
	if !found {
		t.Errorf("share container path not in writable list: %v", s.Writable)
	}
}

func TestSetOverrides(t *testing.T) {
	s := DefaultSpec()
	overrides := []string{
		"network.allow=true",
		"ttl=2h",
		"env.FOO=bar",
		"resources.nproc=64",
		"share=/host:/ctr:ro",
		"user=root",
		"share_process_list=true",
	}
	for _, kv := range overrides {
		if err := s.Set(kv); err != nil {
			t.Errorf("Set(%q): %v", kv, err)
		}
	}
	if !s.Network.Allow || s.TTLSeconds != 7200 || s.Env["FOO"] != "bar" ||
		s.User != "root" || !s.ShareProcessList {
		t.Errorf("overrides not applied: %+v", s)
	}
	if s.Resources.Nproc == nil || *s.Resources.Nproc != 64 {
		t.Errorf("resources override failed")
	}
	if len(s.Shares) != 1 || s.Shares[0].Mode != "ro" {
		t.Errorf("share override failed: %+v", s.Shares)
	}
	if err := s.Set("bogus.key=1"); err == nil {
		t.Error("unknown --set key must error")
	}
}

func TestRlimitsMapping(t *testing.T) {
	s := DefaultSpec()
	if err := s.Set("resources.fsize_bytes=1024"); err != nil {
		t.Fatal(err)
	}
	rl := s.Rlimits()
	if rl["fsize"] != 1024 {
		t.Errorf("fsize mapping: %v", rl)
	}
}

func TestBootstrappingParses(t *testing.T) {
	yaml := `
name: withboot
bootstrapping:
  commands:
    - "echo installed"
  network: true
firewall:
  allow_out:
    - tcp:443
`
	s, err := ParseTemplateBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("rejected: %v", err)
	}
	if s.Bootstrapping == nil || len(s.Bootstrapping.Commands) != 1 {
		t.Fatalf("bootstrapping not parsed: %+v", s.Bootstrapping)
	}
	if s.Bootstrapping.Timeout != 300 {
		t.Errorf("default timeout = %d, want 300", s.Bootstrapping.Timeout)
	}
	if s.Bootstrapping.Network == nil || !*s.Bootstrapping.Network {
		t.Error("bootstrapping.network not parsed")
	}
	if s.Firewall == nil || len(s.Firewall.AllowOut) != 1 {
		t.Errorf("firewall not parsed: %+v", s.Firewall)
	}
}

func TestBootstrappingRejectsEmptyCommand(t *testing.T) {
	_, err := ParseTemplateBytes([]byte("bootstrapping:\n  commands: [\"  \"]\n"))
	if err == nil {
		t.Error("empty command must fail validation")
	}
}

func TestSetBootstrappingAndFirewall(t *testing.T) {
	s := DefaultSpec()
	overrides := []string{
		"bootstrapping.command=curl -fsSL https://x.sh | sh",
		"bootstrapping.network=true",
		"bootstrapping.timeout=60",
		"firewall.allow_out=tcp:443,udp:53",
		"firewall.allow_in=tcp:8080",
		"firewall.dns=false",
	}
	for _, kv := range overrides {
		if err := s.Set(kv); err != nil {
			t.Errorf("Set(%q): %v", kv, err)
		}
	}
	if s.Bootstrapping == nil || len(s.Bootstrapping.Commands) != 1 ||
		s.Bootstrapping.Timeout != 60 || s.Bootstrapping.Network == nil || !*s.Bootstrapping.Network {
		t.Errorf("bootstrapping overrides: %+v", s.Bootstrapping)
	}
	if s.Firewall == nil || len(s.Firewall.AllowOut) != 2 || len(s.Firewall.AllowIn) != 1 ||
		s.Firewall.DNS == nil || *s.Firewall.DNS {
		t.Errorf("firewall overrides: %+v", s.Firewall)
	}
	if err := s.Set("firewall.allow_out=bogus"); err == nil {
		t.Error("invalid firewall rule must fail at Set time")
	}
}
