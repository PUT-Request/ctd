package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Profile renders the Seatbelt policy for a container: writes limited to
// the allow-list, sockets gated by spec.Network, chroot scoped to
// /opt/ctd/containers, signals and process-info limited to the
// container's own sandbox.
// Profile renders the runtime Seatbelt policy for a container.
func Profile(root, self string, spec *Spec) string {
	return profile(root, self, spec, false)
}

// ProfileWith renders the policy with whole-container writes (bootstrap phase:
// writes stay contained to the container's own shadow).
func ProfileWith(root, self string, spec *Spec) string {
	return profile(root, self, spec, true)
}

func profile(root, self string, spec *Spec, writeAll bool) string {
	se := esc(self)

	var b strings.Builder
	b.WriteString("(version 1)\n(deny default)\n\n")

	if writeAll {
		b.WriteString("; bootstrap: writes across the container\n")
		fmt.Fprintf(&b, "(allow file-write* (path-prefix %q))\n", root)
	} else {
		// --- write allow-list ---
		b.WriteString("; write allow-list\n")
		seen := map[string]bool{}
		for _, w := range spec.Writable {
			p := filepath.Join(root, w)
			if seen[p] {
				continue
			}
			seen[p] = true
			fmt.Fprintf(&b, "(allow file-write* (path-prefix %q))\n", p)
		}
	}
	// device io for the container's devfs (host-path form)
	fmt.Fprintf(&b, `; device io for shells (host-path form)
(allow file-write* (path-prefix %q))
(allow file-read* (path-prefix %q))
`, filepath.Join(root, "dev"), filepath.Join(root, "dev"))
	b.WriteString(`
`)
	// --- reads ---
	b.WriteString(`(allow file-read*)

; --- chroot scope ---
`)
	fmt.Fprintf(&b, "(allow file-chroot (path-prefix %q))\n\n", "/opt/ctd/containers")

	// --- process lifecycle ---
	b.WriteString(`(allow process-exec)
(allow process-fork)
`)
	// --- signals and process info: same-sandbox only ---
	if spec.ShareProcessList {
		b.WriteString("(allow process-info*)\n(allow signal)\n")
	} else {
		b.WriteString("(allow process-info* (target self))\n(allow signal (target same-sandbox))\n")
	}

	// --- sysctl; kern.proc denied when the process list is hidden ---
	b.WriteString("(allow sysctl-read)\n")
	if !spec.ShareProcessList {
		b.WriteString(`(deny sysctl-read (sysctl-name "kern.proc"))
(deny sysctl-read (sysctl-name "kern.proc.all"))
(deny sysctl-read (sysctl-name "kern.proc.pid"))
(deny sysctl-read (sysctl-name "kern.proc.pgrp"))
(deny sysctl-read (sysctl-name "kern.proc.sess"))
(deny sysctl-read (sysctl-name "kern.proc.argv"))
(deny sysctl-read (sysctl-name "kern.proc.dropped"))
(deny sysctl-read (sysctl-name "kern.msgq"))
`)
	}
	b.WriteString("\n")

	b.WriteString(networkRules(root, spec))

	// --- syslog/console mach ---
	b.WriteString(`(allow mach-lookup (global-name-regex #".*com\.apple\.syslog.*"))
(allow mach-lookup (global-name "com.apple.system.logger"))

`)
	// --- launcher (pre-chroot) ---
	fmt.Fprintf(&b, "(allow file-read* (path %q))\n(allow process-exec (path %q))\n\n", se, se)

	if extra := strings.TrimSpace(spec.Seatbelt.ExtraRules); extra != "" {
		b.WriteString("; --- template extra_rules ---\n")
		b.WriteString(extra)
		b.WriteString("\n")
	}

	// raw devices: last rules win
	b.WriteString(`
(deny file-write* (path-regex "^.*/dev/rd?isk.*"))
(deny file-read* (path-regex "^.*/dev/rd?isk.*"))
(deny file-write* (path-regex "^.*/dev/bpf.*"))
(deny file-read* (path-regex "^.*/dev/bpf.*"))
(deny file-read* (path-regex "^.*/dev/io$"))
(deny file-read* (path-regex "^.*/dev/kmem"))
(deny file-read* (path-regex "^.*/dev/klog"))
`)
	return b.String()
}

// networkRules compiles the network section: full allow, firewall rules, or deny.
func networkRules(root string, spec *Spec) string {
	if spec.Network.Allow {
		return `; network allowed
(allow network-bind)
(allow network-outbound)
(allow network-inbound)
(allow mach-lookup (global-name "com.apple.networkd"))
(allow mach-lookup (global-name "com.apple.mDNSResponder"))
(allow mach-lookup (global-name "com.apple.dnssd"))
(allow mach-lookup (global-name "com.apple.trustd"))
(allow mach-lookup (global-name "com.apple.SecurityServer"))
(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))
(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))
(allow mach-lookup (global-name "com.apple.diagnosticd"))
(allow system-info)

`
	}
	if spec.Firewall == nil {
		return "; network denied by default\n\n"
	}
	var b strings.Builder
	b.WriteString("; firewall rules\n")
	if spec.Firewall.DNSOn() {
		// sandbox resolves the /var symlink: allow both path forms
		fmt.Fprintf(&b, "(allow network-outbound (literal %q))\n", filepath.Join(root, "var/run/mDNSResponder"))
		fmt.Fprintf(&b, "(allow network-outbound (literal %q))\n", filepath.Join(root, "private/var/run/mDNSResponder"))
		b.WriteString(`(allow mach-lookup (global-name "com.apple.networkd"))
(allow mach-lookup (global-name "com.apple.mDNSResponder"))
(allow mach-lookup (global-name "com.apple.dnssd"))
(allow mach-lookup (global-name "com.apple.trustd"))
(allow mach-lookup (global-name "com.apple.SecurityServer"))
(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))
(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))
(allow system-info)
`)
	}
	b.WriteString(spec.Firewall.outboundSBPL())
	b.WriteString(spec.Firewall.inboundSBPL())
	b.WriteString("\n")
	return b.String()
}

func esc(s string) string { return strings.ReplaceAll(s, `"`, `\"`) }

// WriteProfile renders and writes the profile next to the container.
func WriteProfile(root, self string, spec *Spec) (string, error) {
	p := filepath.Join(filepath.Dir(root), ".ctd-profile.sb")
	if err := os.WriteFile(p, []byte(Profile(root, self, spec)), 0o644); err != nil {
		return "", err
	}
	return p, nil
}
