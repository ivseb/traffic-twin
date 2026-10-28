//go:build !unix

package keyguard

func umask(m int) int { return m }
