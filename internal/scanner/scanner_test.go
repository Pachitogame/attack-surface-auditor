package scanner

import (
	"attack-surface-auditor/internal/audit"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestScanVariosEndpoints(t *testing.T) {
	endpoints := []audit.Endpoint{}
	for i := 0; i < 3; i++ {
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
		endpoints = append(endpoints, endpoint)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	config := audit.ScanConfig{
		NMaxTrabajadores: 2,
		TiempoLimite:     1 * time.Second,
	}
	informe, err := Scan(ctx, config, endpoints)
	if err != nil {
		t.Fatalf("Se esperaba un informe sin errores, pero se obtuvo: %v", err)
	}
	if len(informe) != len(endpoints) {
		t.Fatalf("Se esperaba un informe con %d resultados, pero se obtuvo: %d", len(endpoints), len(informe))
	}
	pendientes := make(map[audit.Endpoint]bool)
	for _, endpoint := range endpoints {
		pendientes[endpoint] = true
	}
	for _, resultado := range informe {
		if resultado.DatosError != nil {
			t.Fatalf("Se esperaba que el puerto estuviera abierto, pero se obtuvo un error: %v", resultado.DatosError)
		}
		if resultado.Resultado != audit.EstadoAbierto {
			t.Fatalf("Se esperaba que el puerto estuviera abierto, pero se obtuvo: %v", resultado.Resultado)
		}
		if !pendientes[resultado.EndpointExaminado] {
			t.Fatalf("Endpoint desconocido o duplicado: %v", resultado.EndpointExaminado)
		}
		delete(pendientes, resultado.EndpointExaminado)
	}
	if len(pendientes) != 0 {
		t.Fatalf("No se examinaron todos los endpoints")
	}
}

func TestScanWithObserver(t *testing.T) {
	endpoints := []audit.Endpoint{}
	for i := 0; i < 3; i++ {
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
		endpoints = append(endpoints, endpoint)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	config := audit.ScanConfig{
		NMaxTrabajadores: 2,
		TiempoLimite:     1 * time.Second,
	}
	observados := []audit.ScanResult{}
	observar := func(resultado audit.ScanResult) {
		observados = append(observados, resultado)
	}
	informe, err := ScanWithObserver(ctx, config, endpoints, observar)
	if err != nil {
		t.Fatalf("Se esperaba un informe sin errores, pero se obtuvo: %v", err)
	}
	if len(informe) != len(endpoints) {
		t.Fatalf("Se esperaba un informe con %d resultados, pero se obtuvo: %d", len(endpoints), len(informe))
	}
	pendientes := make(map[audit.Endpoint]bool)
	for _, endpoint := range endpoints {
		pendientes[endpoint] = true
	}
	for _, resultado := range informe {
		if resultado.DatosError != nil {
			t.Fatalf("Se esperaba que el puerto estuviera abierto, pero se obtuvo un error: %v", resultado.DatosError)
		}
		if resultado.Resultado != audit.EstadoAbierto {
			t.Fatalf("Se esperaba que el puerto estuviera abierto, pero se obtuvo: %v", resultado.Resultado)
		}
		if !pendientes[resultado.EndpointExaminado] {
			t.Fatalf("Endpoint desconocido o duplicado: %v", resultado.EndpointExaminado)
		}
		delete(pendientes, resultado.EndpointExaminado)
	}
	if len(pendientes) != 0 {
		t.Fatalf("No se examinaron todos los endpoints")
	}
	if len(observados) != len(informe) {
		t.Fatalf("Error, se esperaban %d notificaciones, sin embargo se recibieron %d", len(informe), len(observados))
	}
	for i, observado := range observados {
		if observado.EndpointExaminado != informe[i].EndpointExaminado {
			t.Errorf("Notificacion %d: endpoint esperado: %+v, recibido: %+v", i, informe[i].EndpointExaminado, observado.EndpointExaminado)
		}
		if observado.Resultado != informe[i].Resultado {
			t.Errorf("Notificación %d: estado esperado: %v, estado recibido: %v", i, informe[i].Resultado, observado.Resultado)
		}
		if observado.DatosError != nil {
			t.Errorf("Notificacion %d: no se esperaba recibir error, sin embargo se recibió: %v", i, observado.DatosError)
		}
	}
}

func TestScanWithObserverCancelado(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Error, no se pudo crear un oyente %v", err)
	}
	defer listener.Close()
	endpoint := audit.Endpoint{
		DireccionObjetivo: "127.0.0.1",
		Puerto:            listener.Addr().(*net.TCPAddr).Port,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := audit.ScanConfig{
		NMaxTrabajadores: 1,
		TiempoLimite:     time.Second,
	}
	observados := []audit.ScanResult{}
	observar := func(resultado audit.ScanResult) {
		observados = append(observados, resultado)
		cancel()
	}

	informe, err := ScanWithObserver(ctx, config, []audit.Endpoint{endpoint}, observar)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Error, se esperaba context.Canceled, sin embargo se recibió %v", err)
	}
	if len(observados) != 1 {
		t.Fatalf("Error, se esperaba recibir 1 notificacion, sin embargo se recibió: %d", len(observados))
	}
	if len(informe) != 1 {
		t.Fatalf("Error, se esperaba conservar 1 resultado, sin embargo se recibió: %d", len(informe))
	}
	if informe[0].EndpointExaminado != endpoint {
		t.Fatalf("Error, endpoint esperado: %+v, Recibido: %+v", endpoint, informe[0].EndpointExaminado)
	}
	if informe[0].Resultado != audit.EstadoAbierto {
		t.Fatalf("Error, se esperaba un puerto abierto, sin embargo se recibió: %v", informe[0].Resultado)
	}
}
