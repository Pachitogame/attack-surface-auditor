package vuln

import (
	"attack-surface-auditor/internal/fingerprint"
	"testing"
)

func TestQueryFromServiceOpenSSH(t *testing.T) {
	servicio := fingerprint.ServiceInfo{
		Servicio:         "ssh",
		VersionProtocolo: "2.0",
		Software:         "OpenSSH_9.6p1",
	}
	query, ok := QueryFromService(servicio)
	if !ok {
		t.Fatalf("Ha habido un error a la hora de crear el Query")
	}
	if query.Vendor != "openbsd" {
		t.Fatalf("La consulta recibida y la esperada no coinciden. Recibida: %q, Esperada: %q", query.Vendor, "openbsd")
	}
	if query.Product != "openssh" {
		t.Fatalf("El producto recibido y el esperado no coinciden. Recibido: %q, Esperado: %q", query.Product, "openssh")
	}
	if query.Version != "9.6p1" {
		t.Fatalf("La version recibida y la esperada no coinciden. Recibida: %q, Esperada: %q", query.Version, "9.6p1")
	}
}

func TestQueryFromServiceVersionInvalida(t *testing.T) {
	servicio := fingerprint.ServiceInfo{
		Servicio:         "ssh",
		VersionProtocolo: "2.0",
		Software:         "OpenSSH_9.xp1",
	}
	query, ok := QueryFromService(servicio)
	if ok {
		t.Fatal("Se esperaba rechazar la versión inválida, pero fue aceptada")
	}
	if query != (Query{}) {
		t.Fatalf("Se esperaba una consulta vacía; recibida: %+v", query)
	}
}
