package core

import (
	"strings"
	"testing"
)

func TestParseFirewallRule(t *testing.T) {
	valid := map[string][2]string{"tcp:443": {"tcp", "443"}, "udp:53": {"udp", "53"}}
	for in, want := range valid {
		p, port, err := parseFirewallRule(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if p != want[0] || port != want[1] {
			t.Errorf("%q → %s:%s, want %s:%s", in, p, port, want[0], want[1])
		}
	}
	invalid := []struct{ in, wantErr string }{
		{"ip:1.2.3.4", "not supported"},
		{"tcp:10.0.0.0/8", "not supported"},
		{"tcp:8000-9000", "ranges"},
		{"tcp:70000", "invalid port"},
		{"80", "proto:port"},
		{"icmp:80", "tcp or udp"},
	}
	for _, c := range invalid {
		_, _, err := parseFirewallRule(c.in)
		if err == nil {
			t.Errorf("%q: expected error", c.in)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%q: error %q does not contain %q", c.in, err, c.wantErr)
		}
	}
}

func TestFirewallValidationAndExclusion(t *testing.T) {
	s := DefaultSpec()
	s.Network.Allow = true
	s.Firewall = &FirewallSpec{AllowOut: []string{"tcp:443"}}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("network.allow + firewall must be rejected, got %v", err)
	}

	s2 := DefaultSpec()
	s2.Firewall = &FirewallSpec{AllowOut: []string{"ip:1.2.3.4"}}
	if err := s2.Validate(); err == nil {
		t.Error("ip rule must fail validation")
	}

	s3 := DefaultSpec()
	s3.Firewall = &FirewallSpec{AllowOut: []string{"tcp:443"}, AllowIn: []string{"tcp:8080"}}
	if err := s3.Validate(); err != nil {
		t.Errorf("valid firewall rejected: %v", err)
	}
}

func TestFirewallSBPLCompile(t *testing.T) {
	s := DefaultSpec()
	s.Firewall = &FirewallSpec{AllowOut: []string{"tcp:443", "udp:53"}, AllowIn: []string{"tcp:8080"}}
	p := Profile("/opt/ctd/containers/b/root", "/opt/ctd/bin/ctd", s)
	for _, want := range []string{
		`(allow network-outbound (remote tcp "*:443"))`,
		`(allow network-outbound (remote udp "*:53"))`,
		`(allow network-bind (local tcp "*:8080"))`,
		`(allow network-inbound (local tcp "*:8080"))`,
		"/opt/ctd/containers/b/root/var/run/mDNSResponder", // dns bridge socket
	} {
		if !strings.Contains(p, want) {
			t.Errorf("profile missing %q", want)
		}
	}
	if strings.Contains(p, "(allow network-outbound)\n") {
		t.Error("firewall profile must not blanket-allow network")
	}
	// dns off: no bridge socket rule
	s.Firewall.DNS = boolPtr(false)
	p = Profile("/opt/ctd/containers/b/root", "/opt/ctd/bin/ctd", s)
	if strings.Contains(p, "mDNSResponder") {
		t.Error("dns=false must drop the resolver socket rule")
	}
}

func TestDnsEnabled(t *testing.T) {
	s := DefaultSpec()
	if s.dnsEnabled() {
		t.Error("deny-by-default must have dns off")
	}
	s.Network.Allow = true
	if !s.dnsEnabled() {
		t.Error("full network implies dns")
	}
	s.Network.Allow = false
	s.Firewall = &FirewallSpec{}
	if !s.dnsEnabled() {
		t.Error("firewall defaults to dns on")
	}
	s.Firewall.DNS = boolPtr(false)
	if s.dnsEnabled() {
		t.Error("firewall.dns=false must disable dns")
	}
}

func TestFirstAllowTCPPort(t *testing.T) {
	f := &FirewallSpec{AllowOut: []string{"udp:53", "tcp:22"}}
	if got := f.firstAllowTCPPort(); got != "22" {
		t.Errorf("first tcp port = %q, want 22", got)
	}
	if got := (&FirewallSpec{}).firstAllowTCPPort(); got != "" {
		t.Errorf("empty firewall → %q", got)
	}
}

func boolPtr(b bool) *bool { return &b }
