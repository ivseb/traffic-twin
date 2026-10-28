//go:build unix

package keyguard

import "syscall"

func umask(m int) int { return syscall.Umask(m) }
