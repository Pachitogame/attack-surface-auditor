//go:build !windows

package scanner

import (
	"errors"
	"syscall"
)

const wsaECONNREFUSED syscall.Errno = 10061

func esConexionRechazada(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
