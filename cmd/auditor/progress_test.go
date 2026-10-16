package main

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"
)

func TestMostrarProgresoSinResultados(t *testing.T) {
	var salida bytes.Buffer
	var completados atomic.Int64
	ticks := make(chan time.Time)
	detener := make(chan struct{})
	go func() {
		ticks <- time.Time{}
		close(detener)
	}()
	mostrarProgreso(&salida, &completados, 100, ticks, detener)
	esperado := "Progreso: 0/100 puertos examinados\n"
	if salida.String() != esperado {
		t.Fatalf("Error, salida esperada: %q, salida recibida: %q", esperado, salida.String())
	}
}
func TestMostrarProgresoDetenidoSinTicks(t *testing.T) {
	var salida bytes.Buffer
	var completados atomic.Int64
	ticks := make(chan time.Time)
	detener := make(chan struct{})
	close(detener)
	mostrarProgreso(&salida, &completados, 100, ticks, detener)
	if salida.Len() != 0 {
		t.Fatalf("No se esperaba ninguna salida, salida recibida: %q", salida.String())
	}
}
