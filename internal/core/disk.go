package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DiskUsage returns the container's disk footprint in bytes: the container
// tree plus its image shadow, EXCLUDING the mounted image itself (du -x
// stays on one filesystem, so the ro image mount at <root>/img is skipped).
// Note: APFS clones share blocks with the base tree — usage counts a clone's
// full apparent size, so it is a conservative admission figure.
func DiskUsage(name string) (int64, error) {
	dir := Dir(name)
	if _, err := os.Stat(dir); err != nil {
		return 0, err
	}
	out, err := Run("du", "-skx", dir)
	if err != nil {
		return 0, fmt.Errorf("du: %w", err)
	}
	var kb int64
	if _, err := fmt.Sscanf(strings.Fields(out)[0], "%d", &kb); err != nil {
		return 0, fmt.Errorf("du output: %q", out)
	}
	return kb * 1024, nil
}

// CheckDiskQuota refuses an exec when the container's usage exceeds
// resources.disk_max_bytes (>0). Skips entirely when unset.
func CheckDiskQuota(name string, spec *Spec) error {
	if spec == nil || spec.Resources.DiskMaxBytes == nil || *spec.Resources.DiskMaxBytes == 0 {
		return nil
	}
	max := int64(*spec.Resources.DiskMaxBytes)
	used, err := DiskUsage(name)
	if err != nil {
		return err
	}
	if used > max {
		return fmt.Errorf("disk quota exceeded: %s used of %s allowed (resources.disk_max_bytes)",
			HumanBytes(used), HumanBytes(max))
	}
	return nil
}

// duSkx returns du -skx in KB for a path (used by ps/inspect displays).
func duSkx(path string) int64 {
	out, err := Run("du", "-skx", path)
	if err != nil {
		return -1
	}
	var kb int64
	if _, err := fmt.Sscanf(strings.Fields(out)[0], "%d", &kb); err != nil {
		return -1
	}
	return kb * 1024
}

// diskFootprint is a thin wrapper used by describe().
func diskFootprint(name string) int64 {
	v, err := DiskUsage(name)
	if err != nil {
		if os.IsNotExist(err) || filepath.IsAbs(name) {
			return 0
		}
		return 0
	}
	return v
}
