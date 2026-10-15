package scanner

import (
	"attack-surface-auditor/internal/audit"
	"context"
	"errors"
	"net"
	"strconv"
	"time"
)

func scanEndpoint(ctx context.Context, endpoint audit.Endpoint, timeout time.Duration) audit.ScanResult {
	puertoTexto := strconv.Itoa(endpoint.Puerto)
	direccion := net.JoinHostPort(endpoint.DireccionObjetivo, puertoTexto)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", direccion)
	if err != nil {
		estado := audit.EstadoIndeterminado
		switch ctx.Err() {
		case context.DeadlineExceeded:
			estado = audit.EstadoTimeout
		case context.Canceled:
			estado = audit.EstadoCancelado
		default:
			var errRed net.Error
			if errors.As(err, &errRed) && errRed.Timeout() {
				estado = audit.EstadoTimeout
			} else if esConexionRechazada(err) {
				estado = audit.EstadoCerrado
			}
		}
		return audit.ScanResult{
			EndpointExaminado: endpoint,
			Resultado:         estado,
			DatosError:        err,
		}
	}
	defer conn.Close()
	return audit.ScanResult{
		EndpointExaminado: endpoint,
		Resultado:         audit.EstadoAbierto,
		DatosError:        nil,
	}
}

func worker(ctx context.Context, jobs <-chan audit.Endpoint, results chan<- audit.ScanResult, timeout time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case endpoint, ok := <-jobs:
			if !ok {
				return
			}
			resultado := scanEndpoint(ctx, endpoint, timeout)
			select {
			case results <- resultado:

			case <-ctx.Done():
				return
			}
		}
	}
}
