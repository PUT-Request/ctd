package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDiskQuota(t *testing.T) {
	// unset → no gate
	if err := CheckDiskQuota("x", &Spec{}); err != nil {
		t.Fatalf("unset max should skip gate: %v", err)
	}
	if err := CheckDiskQuota("x", nil); err != nil {
		t.Fatalf("nil spec should skip gate: %v", err)
	}
}

func TestDiskUsageCountsBytes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), make([]byte, 3000), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "g"), make([]byte, 7000), 0o644); err != nil {
		t.Fatal(err)
	}
	got := duSkx(dir)
	// du rounds up to KB blocks; at least the payload must be visible.
	if got < 10_000 {
		t.Fatalf("duSkx = %d, want >= 10000 (allocated bytes of 10KB payload)", got)
	}
}

func TestHumanBytesDisk(t *testing.T) {
	if HumanBytes(0) != "0B" {
		t.Fatalf("HumanBytes(0) = %q", HumanBytes(0))
	}
	if HumanBytes(2147483648) != "2.0GB" {
		t.Fatalf("HumanBytes(2Gi) = %q", HumanBytes(2147483648))
	}
}
