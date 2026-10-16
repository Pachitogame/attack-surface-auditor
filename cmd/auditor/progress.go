package main

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

func mostrarProgreso(destino io.Writer, completados *atomic.Int64, total int, ticks <-chan time.Time, detener <-chan struct{}) {
	for {
		select {
		case <-detener:
			return
		case <-ticks:
			fmt.Fprintf(destino, "Progreso: %d/%d puertos examinados\n", completados.Load(), total)
		}
	}
}
