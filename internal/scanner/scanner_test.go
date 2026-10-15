package scanner

import (
	"attack-surface-auditor/internal/audit"
	"context"
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
