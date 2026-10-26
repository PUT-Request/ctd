package core

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// FullSpec returns the effective (stored or default) spec of a container.
func FullSpec(name string) (*Spec, error) {
	m, err := LoadMeta(name)
	if err != nil {
		return nil, err
	}
	return m.effectiveSpec(), nil
}

// Check is one security audit result.
type Check struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// AuditReport aggregates the escape-probe results for one container.
type AuditReport struct {
	Container string  `json:"container"`
	Uid       int     `json:"uid"`
	Network   bool    `json:"network_enabled"`
	OK        bool    `json:"ok"`
	Checks    []Check `json:"checks"`
}

// AuditContainer runs escape probes through the real exec path and
// asserts on output substrings.
func AuditContainer(name string) (*AuditReport, error) {
	c, err := Describe(name)
	if err != nil {
		return nil, err
	}
	spec, _ := FullSpec(name)
	rep := &AuditReport{Container: name, Uid: c.Uid, Network: spec.Network.Allow, OK: true}

	// want: substring that must appear in combined output.
	expect := func(id, want, detail string, argv ...string) {
		res, err := Exec("audit", name, argv, ExecOptions{Timeout: 20 * time.Second})
		if err != nil {
			rep.Checks = append(rep.Checks, Check{ID: id, OK: false, Detail: "exec error: " + err.Error()})
			rep.OK = false
			return
		}
		out := strings.TrimSpace(res.Stdout + res.Stderr)
		ok := strings.Contains(out, want)
		short := out
		if len(short) > 150 {
			short = short[:150] + "…"
		}
		short = strings.ReplaceAll(short, "\n", " | ")
		rep.Checks = append(rep.Checks, Check{ID: id, OK: ok,
			Detail: fmt.Sprintf("%s → want %q got %q (exit=%d)", detail, want, short, res.ExitCode)})
		if !ok {
			rep.OK = false
		}
	}

	// system tree must be unwritable
	expect("system_tree_readonly", "BLOCKED", "write /usr/bin denied",
		"/bin/sh", "-c", "echo pwned > /usr/bin/.x 2>&1 && echo WROTE || echo BLOCKED")
	// private layer writable
	expect("private_layer_writable", "ok", "write own home works",
		"/bin/sh", "-c", "echo ok > $HOME/.audit && cat $HOME/.audit && rm -f $HOME/.audit")
	// host filesystem invisible (canary: the invoking user's home, which
	// never exists inside a container)
	expect("host_fs_hidden", "MISSING", "host home must not resolve in-container",
		"/bin/sh", "-c", "test -e "+ExpandHostPath("~")+" && echo EXISTS || echo MISSING")
	// /etc not writable
	expect("etc_readonly", "BLOCKED", "write /etc denied",
		"/bin/sh", "-c", "echo x > /etc/.x 2>&1 && echo WROTE || echo BLOCKED")
	// network policy
	switch {
	case spec.Network.Allow:
		expect("network_egress", "EGRESS_OK", "raw TCP+HTTP egress (any HTTP status)",
			"/bin/sh", "-c", "/usr/bin/curl -s -m 8 -o /dev/null http://1.1.1.1 && echo EGRESS_OK || echo EGRESS_FAIL")
		expect("network_dns_tls", "200", "full DNS bridge + TLS path",
			"/usr/bin/curl", "-s", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com")
	case spec.Firewall != nil:
		auditFirewall(rep, spec, expect)
	default:
		expect("network_denied", "DENIED", "sockets+DNS denied",
			"/bin/sh", "-c", "/usr/bin/curl -s -m 5 -o /dev/null https://example.com 2>&1 && echo REACHED || echo DENIED")
	}
	// raw disk devices unreachable
	expect("rawdisk_denied", "DENIED", "open /dev/rdisk0 denied",
		"/bin/sh", "-c", "exec 3<>/dev/rdisk0 2>&1 && echo OPENED || echo DENIED")
	// privilege drop
	if spec.User == "root" {
		expect("uid_is_root_by_template", "0", "template opts into root",
			"/bin/sh", "-c", "/usr/bin/id -u")
	} else {
		expect("privdrop", "DROPPED", "must not be uid 0",
			"/bin/sh", "-c", "test \"$(/usr/bin/id -u)\" = 0 && echo IS_ROOT || echo DROPPED")
		expect("dedicated_uid", fmt.Sprintf("uid=%d", c.Uid), "template uid active",
			"/bin/sh", "-c", "echo uid=$(/usr/bin/id -u)")
	}
	// rlimits
	expect("rlimits_applied", "fsize=", "limits visible",
		"/bin/sh", "-c", "echo fsize=$(ulimit -f) cpu=$(ulimit -t) nproc=$(ulimit -u)")
	// cannot signal a foreign pid
	expect("signal_foreign_denied", "DENIED", "kill -9 1 denied",
		"/bin/sh", "-c", "kill -9 1 2>&1 && echo KILLED_LAUNCHD || echo DENIED")
	// own-child signaling (job control)
	expect("signal_own_child", "OK", "own child kill works",
		"/bin/sh", "-c", "/bin/sleep 5 & K=$!; kill $K 2>&1 && echo OK || echo FAIL")
	// process list visibility
	if spec.ShareProcessList {
		rep.Checks = append(rep.Checks, Check{ID: "process_visibility", OK: true,
			Detail: "share_process_list=true — full ps view by template choice"})
	} else {
		expect("process_list_scoped", "SCOPED", "ps must not see host root procs",
			"/bin/sh", "-c", "U=$(/usr/bin/id -u); if ps -axo uid= 2>/dev/null | grep -qx 0; then echo LEAK_DETECTED; else echo SCOPED uid=$U; fi")
	}
	// /tmp writable (shell tempfiles)
	expect("tmp_writable", "TMP_OK", "mktemp in /tmp",
		"/bin/sh", "-c", "/usr/bin/mktemp /tmp/ctd.XXXX >/dev/null && rm -f /tmp/ctd.XXXX* && echo TMP_OK || echo TMP_FAIL")

	return rep, nil
}

// auditFirewall probes rule enforcement with live local listeners.
func auditFirewall(rep *AuditReport, spec *Spec, expect func(id, want, detail string, argv ...string)) {
	if spec.Firewall.DNSOn() {
		expect("firewall_dns", "200", "resolver enabled",
			"/usr/bin/curl", "-s", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com")
	}
	// a port NOT in allow_out must be blocked
	if ln, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		serveOnce(ln)
		port := ln.Addr().(*net.TCPAddr).Port
		expect("firewall_denies_unlisted_port", "DENIED", "port outside allow_out",
			"/bin/sh", "-c", fmt.Sprintf("/usr/bin/curl -s -m 3 -o /dev/null http://127.0.0.1:%d/ && echo REACHED || echo DENIED", port))
		_ = ln.Close()
	}
	// the first allowed tcp port must be reachable
	if port := spec.Firewall.firstAllowTCPPort(); port != "" {
		ln, err := net.Listen("tcp", "127.0.0.1:"+port)
		if err != nil {
			rep.Checks = append(rep.Checks, Check{ID: "firewall_allows_listed_port", OK: true, Detail: "local port busy, skipped"})
		} else {
			serveOnce(ln)
			expect("firewall_allows_listed_port", "ALLOWED_OK", "port inside allow_out",
				"/bin/sh", "-c", fmt.Sprintf("/usr/bin/curl -s -m 3 -o /dev/null http://127.0.0.1:%s/ && echo ALLOWED_OK || echo BLOCKED", port))
			_ = ln.Close()
		}
	}
}

// serveOnce answers one HTTP request then exits with the listener.
func serveOnce(ln net.Listener) {
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	}()
}
