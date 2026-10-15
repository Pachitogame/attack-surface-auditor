package scanner

import (
	"fmt"
	"syscall"
	"testing"
)

func TestConexionRechazadaWindows(t *testing.T) {
	err := fmt.Errorf("Error, fallo al conectar: %w", syscall.Errno(10061))
	if !esConexionRechazada(err) {
		t.Fatalf("Error, se recibió false, cuando debería haberse recibido true")
	}
	if esConexionRechazada(nil) {
		t.Fatal("Error, se recibió true cuando debería haberte devuelto false")
	}
	err = syscall.Errno(10060)
	if esConexionRechazada(err) {
		t.Fatalf("Error, se recibió true, cuando debería haberse recibido false")
	}
}
