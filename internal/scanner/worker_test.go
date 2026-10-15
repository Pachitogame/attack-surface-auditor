package scanner

import (
	"attack-surface-auditor/internal/audit"
	"context"
	"net"
	"testing"
	"time"
)

func TestScanEndpointAbierto(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("No se pudo crear un oyente: %v", err)
	}
	defer listener.Close()
	puertoAsignado := listener.Addr().(*net.TCPAddr).Port
	endpoint := audit.Endpoint{
		DireccionObjetivo: "127.0.0.1",
		Puerto:            puertoAsignado,
	}
	resultado := scanEndpoint(context.Background(), endpoint, time.Second)
	if resultado.DatosError != nil {
		t.Fatalf("Se esperaba que el puerto estuviera abierto, pero se obtuvo un error: %v", resultado.DatosError)
	}
	if resultado.Resultado != audit.EstadoAbierto {
		t.Fatalf("Se esperaba que el puerto estuviera abierto, pero se obtuvo: %v", resultado.Resultado)
	}
	if resultado.EndpointExaminado != endpoint {
		t.Fatalf("Se esperaba el endpoint examinado %v, pero se obtuvo: %v", endpoint, resultado.EndpointExaminado)
	}

}
func TestScanEndpointCancelado(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("No se pudo crear un oyente: %v", err)
	}
	defer listener.Close()
	puertoAsignado := listener.Addr().(*net.TCPAddr).Port
	endpoint := audit.Endpoint{
		DireccionObjetivo: "127.0.0.1",
		Puerto:            puertoAsignado,
	}
	cxt, cancel := context.WithCancel(context.Background())
	cancel()
	resultado := scanEndpoint(cxt, endpoint, time.Second)
	if resultado.DatosError == nil {
		t.Fatal("se esperaba un error por cancelación, pero se recibió nil")
	}
	if resultado.Resultado != audit.EstadoCancelado {
		t.Fatalf("Se esperaba que el puerto estuviera cancelado, pero se obtuvo: %v", resultado.Resultado)
	}
	if resultado.EndpointExaminado != endpoint {
		t.Fatalf("Se esperaba el endpoint examinado %v, pero se obtuvo: %v", endpoint, resultado.EndpointExaminado)
	}
}
func TestWorkerCanceladoSinConsumidor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jobs := make(chan audit.Endpoint, 1)
	results := make(chan audit.ScanResult)
	terminado := make(chan struct{})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("No se pudo crear un oyente: %v", err)
	}
	defer listener.Close()
	puertoAsignado := listener.Addr().(*net.TCPAddr).Port
	endpoint := audit.Endpoint{
		DireccionObjetivo: "127.0.0.1",
		Puerto:            puertoAsignado,
	}
	jobs <- endpoint
	go func() {
		defer close(terminado)
		worker(ctx, jobs, results, time.Second)
	}()
	err = listener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		t.Fatalf("No se pudo establecer el timeout: %v", err)
	}
	conexion, err := listener.Accept()
	if err != nil {
		t.Fatalf("No se pudo aceptar la conexión: %v", err)
	}
	defer conexion.Close()
	cancel()
	select {
	case <-terminado:

	case <-time.After(2 * time.Second):
		t.Fatal("El trabajador no terminó después de la cancelación")
	}

}
