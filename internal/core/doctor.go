package core

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Probe is one doctor check.
type Probe struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// DoctorReport aggregates all probes.
type DoctorReport struct {
	OK      bool     `json:"ok"`
	Probes  []Probe  `json:"probes"`
	DiskAdd string   `json:"disk_added_total"`
	Notes   []string `json:"notes"`
}

func probe(id string, fn func() (bool, string)) Probe {
	ok, detail := fn()
	return Probe{ID: id, OK: ok, Detail: detail}
}

// hasBin checks PATH for a binary.
func hasBin(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Doctor runs environment checks and reports.
func Doctor() *DoctorReport {
	rep := &DoctorReport{}
	add := func(p Probe) { rep.Probes = append(rep.Probes, p) }

	add(probe("arch", func() (bool, string) {
		out, _ := Run("uname", "-m")
		return strings.TrimSpace(out) == "arm64", strings.TrimSpace(out)
	}))
	add(probe("macos", func() (bool, string) {
		out, _ := Run("sw_vers", "-productVersion")
		return true, "macOS " + strings.TrimSpace(out)
	}))
	add(probe("sip", func() (bool, string) {
		out, _ := Run("csrutil", "status")
		s := strings.TrimSpace(out)
		// SIP on is fine — we never touch protected paths.
		return true, s
	}))
	add(probe("tools", func() (bool, string) {
		need := []string{"hdiutil", "diskutil", "sandbox-exec", "codesign", "mount", "umount"}
		var missing []string
		for _, t := range need {
			if !hasBin(t) {
				missing = append(missing, t)
			}
		}
		return len(missing) == 0, strings.Join(missing, ",")
	}))
	add(probe("root", func() (bool, string) {
		return os.Geteuid() == 0, fmt.Sprintf("euid=%d", os.Geteuid())
	}))
	add(probe("dyld_cache_source", func() (bool, string) {
		dmg, err := FindDMG()
		if err != nil {
			return false, err.Error()
		}
		return true, dmg
	}))
	add(probe("recovery_mount", func() (bool, string) {
		mp, err := RecoveryMountPoint()
		if err != nil {
			return false, err.Error()
		}
		return true, mp
	}))
	add(probe("base_prepared", func() (bool, string) {
		m, err := LoadManifest()
		if err != nil {
			return false, err.Error()
		}
		return true, fmt.Sprintf("%d tools re-signed, tree %s",
			len(m.ToolsSigned), HumanBytes(m.TreeBytes))
	}))
	add(probe("cp_clone", func() (bool, string) {
		// clonefile within same volume works (used by create)
		src := "/tmp/.ctd-probe-src"
		_ = os.WriteFile(src, []byte("probe"), 0o644)
		_ = os.Remove("/tmp/.ctd-probe-clone")
		_, err := Run("cp", "-c", src, "/tmp/.ctd-probe-clone")
		_ = os.Remove(src)
		_ = os.Remove("/tmp/.ctd-probe-clone")
		if err != nil {
			return false, err.Error()
		}
		return true, "APFS clonefile ok"
	}))
	add(probe("containers", func() (bool, string) {
		all, err := List()
		if err != nil {
			return false, err.Error()
		}
		return true, fmt.Sprintf("%d container(s)", len(all))
	}))

	// Disk accounting: only what ctd physically added. -x keeps du from
	// walking into mounted container images (those bytes belong to the
	// pre-existing dmg, not to us); shadows are counted allocated, but
	// APFS clones share blocks with base.shadow — marginal cost is the
	// shadow's unique writes, which df-delta measures best. We report
	// both: allocated size of our own files, excluding image mounts.
	rep.DiskAdd = ownAllocated()

	rep.Notes = []string{
		"Base image: Recovery dmg + APFS copy-on-write shadow.",
		"Container shadows are clones of base.shadow (cost only what is written).",
		"Curated tools are re-signed plain ad-hoc for in-container exec.",
		"Isolation: chroot + Seatbelt + rlimits + privilege drop. Guardrail sandbox, not a VM boundary.",
	}

	rep.OK = true
	for _, p := range rep.Probes {
		// root probe failing is ok for read-only doctor; everything else must pass
		if !p.OK && p.ID != "root" && p.ID != "base_prepared" {
			rep.OK = false
		}
	}
	return rep
}

// ownAllocated reports ctd's disk footprint, staying on one filesystem
// so mounted images are excluded.
func ownAllocated() string {
	out, err := Run("du", "-skx", OptDir)
	if err != nil {
		return "unknown"
	}
	var kb int64
	if _, err := fmt.Sscanf(strings.Fields(out)[0], "%d", &kb); err != nil {
		return "unknown"
	}
	return HumanBytes(kb * 1024)
}
