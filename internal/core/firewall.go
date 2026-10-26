package core

import (
	"fmt"
	"strconv"
	"strings"
)

// FirewallSpec compiles template rules into Seatbelt network filters.
// Expressible on this system: per-port, all-hosts (tcp/udp outbound) and
// per-port bind/listen. Remote IP / CIDR / port-range rules are rejected
// at validation with a clear error (Seatbelt requires host * or
// localhost and a single port).
type FirewallSpec struct {
	DNS      *bool    `json:"dns,omitempty" yaml:"dns,omitempty"` // resolver bridge, default on
	AllowOut []string `json:"allow_out,omitempty" yaml:"allow_out,omitempty"`
	AllowIn  []string `json:"allow_in,omitempty" yaml:"allow_in,omitempty"`
}

// DNSOn returns whether name resolution is enabled (default true).
func (f *FirewallSpec) DNSOn() bool {
	return f.DNS == nil || *f.DNS
}

// dnsEnabled: resolver available for this spec (full network or firewall+dns).
func (s *Spec) dnsEnabled() bool {
	if s.Network.Allow {
		return true
	}
	if s.Firewall != nil {
		return s.Firewall.DNSOn()
	}
	return false
}

// firewallActive: rule-based filtering in effect (mutually exclusive with network.allow).
func (s *Spec) firewallActive() bool { return s.Firewall != nil && !s.Network.Allow }

// parseFirewallRule validates "tcp:443" style entries → (proto, port).
func parseFirewallRule(entry string) (proto, port string, err error) {
	e := strings.TrimSpace(entry)
	if strings.HasPrefix(e, "ip:") || strings.Contains(e, "/") {
		return "", "", fmt.Errorf("rule %q: remote IP/CIDR rules are not supported by Seatbelt (host must be * or localhost, single port only) — use port rules or seatbelt.extra_rules", entry)
	}
	if strings.Contains(e, "-") {
		return "", "", fmt.Errorf("rule %q: port ranges are not supported by Seatbelt — list single ports instead", entry)
	}
	proto, port, ok := strings.Cut(e, ":")
	if !ok {
		return "", "", fmt.Errorf("rule %q: expected proto:port, e.g. tcp:443", entry)
	}
	if proto != "tcp" && proto != "udp" {
		return "", "", fmt.Errorf("rule %q: protocol must be tcp or udp", entry)
	}
	n, convErr := strconv.Atoi(port)
	if convErr != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("rule %q: invalid port (1-65535)", entry)
	}
	return proto, port, nil
}

// Validate checks every rule.
func (f *FirewallSpec) Validate() error {
	for _, r := range f.AllowOut {
		if _, _, err := parseFirewallRule(r); err != nil {
			return err
		}
	}
	for _, r := range f.AllowIn {
		if _, _, err := parseFirewallRule(r); err != nil {
			return err
		}
	}
	return nil
}

// outboundSBPL renders allow_out rules.
func (f *FirewallSpec) outboundSBPL() string {
	var b strings.Builder
	for _, r := range f.AllowOut {
		if proto, port, err := parseFirewallRule(r); err == nil {
			fmt.Fprintf(&b, "(allow network-outbound (remote %s \"*:%s\"))\n", proto, port)
		}
	}
	return b.String()
}

// inboundSBPL renders allow_in rules (bind + inbound).
func (f *FirewallSpec) inboundSBPL() string {
	var b strings.Builder
	for _, r := range f.AllowIn {
		if proto, port, err := parseFirewallRule(r); err == nil {
			fmt.Fprintf(&b, "(allow network-bind (local %s \"*:%s\"))\n", proto, port)
			fmt.Fprintf(&b, "(allow network-inbound (local %s \"*:%s\"))\n", proto, port)
		}
	}
	return b.String()
}

// firstAllowTCPPort returns the first explicit outbound tcp port (for audit probes).
func (f *FirewallSpec) firstAllowTCPPort() string {
	for _, r := range f.AllowOut {
		if proto, port, err := parseFirewallRule(r); err == nil && proto == "tcp" {
			return port
		}
	}
	return ""
}
