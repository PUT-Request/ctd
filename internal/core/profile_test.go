package core

import (
	"strings"
	"testing"
)

const testRoot = "/opt/ctd/containers/box/root"
const testSelf = "/opt/ctd/bin/ctd"

func TestProfileWriteAllowList(t *testing.T) {
	s := DefaultSpec()
	p := Profile(testRoot, testSelf, s)
	// every writable path must be allow-listed with the HOST path form
	for _, w := range s.Writable {
		want := `path-prefix "` + testRoot + w + `"`
		if !strings.Contains(p, want) {
			t.Errorf("missing write allow for %s (want %s)", w, want)
		}
	}
	// system tree must NOT be writable
	if strings.Contains(p, `path-prefix "`+testRoot+`/usr`) {
		t.Error("system tree must not be in the write allow-list")
	}
}

func TestProfileNetworkGate(t *testing.T) {
	off := Profile(testRoot, testSelf, DefaultSpec())
	if strings.Contains(off, "network-outbound") {
		t.Error("network rules present while network.allow=false")
	}
	on := DefaultSpec()
	if err := on.Set("network.allow=true"); err != nil {
		t.Fatal(err)
	}
	p := Profile(testRoot, testSelf, on)
	for _, want := range []string{"network-outbound", "network-bind", `com.apple.mDNSResponder`, "com.apple.trustd"} {
		if !strings.Contains(p, want) {
			t.Errorf("network profile missing %q", want)
		}
	}
}

func TestProfileChrootScoped(t *testing.T) {
	p := Profile(testRoot, testSelf, DefaultSpec())
	if !strings.Contains(p, `(allow file-chroot (path-prefix "/opt/ctd/containers"))`) {
		t.Error("file-chroot must be scoped to /opt/ctd/containers")
	}
	// never a blanket chroot
	if strings.Contains(p, "(allow file-chroot)") {
		t.Error("blanket file-chroot allowed")
	}
}

func TestProfileRawDeviceDeniesComeLast(t *testing.T) {
	p := Profile(testRoot, testSelf, DefaultSpec())
	// raw-device denies must follow the blanket allow (last rule wins)
	readAll := strings.Index(p, "(allow file-read*)")
	denyDisk := strings.Index(p, `deny file-read* (path-regex "^.*/dev/rd?isk.*"`)
	if denyDisk == -1 {
		t.Fatal("raw disk read-deny missing")
	}
	if readAll != -1 && denyDisk < readAll {
		t.Error("raw-device denies must come after the blanket file-read allow (last rule wins)")
	}
	if strings.Index(p, "deny file-read* (path-regex \"^.*/dev/rd?isk.*\")") <
		strings.LastIndex(p, "(allow file-read*)") {
		t.Error("a later file-read allow would re-enable raw disk reads")
	}
}

func TestProfileSignalsSameSandboxByDefault(t *testing.T) {
	hidden := Profile(testRoot, testSelf, DefaultSpec())
	if !strings.Contains(hidden, "(allow signal (target same-sandbox))") {
		t.Error("default profile must scope signals to same-sandbox")
	}
	if strings.Contains(hidden, "(allow process-info* (target self))") != true {
		t.Error("default profile must scope process-info to self")
	}
	shared := DefaultSpec()
	shared.ShareProcessList = true
	p := Profile(testRoot, testSelf, shared)
	if !strings.Contains(p, "(allow process-info*)") {
		t.Error("share_process_list=true must allow full process-info")
	}
}

func TestProfileExtraRulesAppended(t *testing.T) {
	s := DefaultSpec()
	s.Seatbelt.ExtraRules = `(allow mach-lookup (global-name "com.apple.mydaemon"))`
	p := Profile(testRoot, testSelf, s)
	if !strings.Contains(p, "com.apple.mydaemon") {
		t.Error("extra_rules not appended")
	}
}
