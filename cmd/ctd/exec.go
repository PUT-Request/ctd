package main

import "syscall"

// syscallExec replaces the current process (used for sudo re-exec).
func syscallExec(name string, argv []string, envv []string) error {
	return syscall.Exec(name, argv, envv)
}
