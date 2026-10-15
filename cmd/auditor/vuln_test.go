package main

import (
	"attack-surface-auditor/internal/audit"
	"attack-surface-auditor/internal/vuln"
	"context"
	"errors"
	"testing"
	"time"
)

type consultorSimulado struct{}
type consultorBloqueado struct {
	iniciadas chan struct{}
}

func (consultorSimulado) Lookup(ctx context.Context, query vuln.Query, config vuln.Config) ([]vuln.CVE, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var cves []vuln.CVE
	cves = append(cves, vuln.CVE{
		ID:          "CVE-2024-1234",
		Description: query.Version,
	})
	return cves, nil
}
func (c consultorBloqueado) Lookup(ctx context.Context, query vuln.Query, config vuln.Config) ([]vuln.CVE, error) {
	select {
	case c.iniciadas <- struct{}{}:

	case <-ctx.Done():
		return nil, ctx.Err()
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestEjecutarConsultasVuln(t *testing.T) {
	consultas := []consultaVuln{
		{Endpoint: audit.Endpoint{
			DireccionObjetivo: "127.0.0.1",
			Puerto:            22,
		},
			Query: vuln.Query{
				Vendor:  "openbsd",
				Product: "openssh",
				Version: "9.6p1",
			},
		},
		{Endpoint: audit.Endpoint{
			DireccionObjetivo: "127.0.0.1",
			Puerto:            2222,
		},
			Query: vuln.Query{
				Vendor:  "openbsd",
				Product: "openssh",
				Version: "9.7p1",
			},
		},
		{Endpoint: audit.Endpoint{
			DireccionObjetivo: "127.0.0.1",
			Puerto:            2223,
		},
			Query: vuln.Query{
				Vendor:  "openbsd",
				Product: "openssh",
				Version: "9.8p1",
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	config := vuln.Config{
		Timeout:      time.Second,
		MaxBodyBytes: 4096,
	}
	resultados, err := ejecutarConsultasVuln(ctx, consultorSimulado{}, config, consultas, 2)
	if err != nil {
		t.Fatalf("Se ha producido un error a la hora de ejecutar la consulta. %v", err)
	}
	if len(resultados) != 3 {
		t.Fatalf("Error, se esperaban 3 resultados, sin embargo se han recibido %d", len(resultados))
	}
	pendientes := make(map[audit.Endpoint]string)
	for _, consulta := range consultas {
		pendientes[consulta.Endpoint] = consulta.Query.Version
	}
	for _, resultado := range resultados {
		if resultado.Error != nil {
			t.Fatalf("Se ha encontrado un error en uno de los resultados. %v", resultado.Error)
		}
		versionEsperada, existe := pendientes[resultado.Endpoint]
		if !existe {
			t.Fatalf("Endpoint desconocido o duplicado: %+v", resultado.Endpoint)
		}
		if len(resultado.CVEs) != 1 {
			t.Fatalf("Se esperaba un CVE, se han recibido %d", len(resultado.CVEs))
		}
		if resultado.CVEs[0].ID != "CVE-2024-1234" {
			t.Fatalf("Endpoint %+v: ID esperado %q: Recibido: %q", resultado.Endpoint, "CVE-2024-1234", resultado.CVEs[0].ID)
		}
		if resultado.CVEs[0].Description != versionEsperada {
			t.Fatalf("Endpoint %+v: Versión esperada %q, Recibida: %q", resultado.Endpoint, versionEsperada, resultado.CVEs[0].Description)
		}
		delete(pendientes, resultado.Endpoint)
	}
	if len(pendientes) != 0 {
		t.Fatalf("Error, no se eliminaron todos los endpoints de la lista de pendientes")
	}
}

func TestEjecutarConsultasVulnCancelado(t *testing.T) {
	consultas := []consultaVuln{
		{Endpoint: audit.Endpoint{
			DireccionObjetivo: "127.0.0.1",
			Puerto:            22,
		},
			Query: vuln.Query{
				Vendor:  "openbsd",
				Product: "openssh",
				Version: "9.6p1",
			},
		},
		{Endpoint: audit.Endpoint{
			DireccionObjetivo: "127.0.0.1",
			Puerto:            2222,
		},
			Query: vuln.Query{
				Vendor:  "openbsd",
				Product: "openssh",
				Version: "9.7p1",
			},
		},
		{Endpoint: audit.Endpoint{
			DireccionObjetivo: "127.0.0.1",
			Puerto:            2223,
		},
			Query: vuln.Query{
				Vendor:  "openbsd",
				Product: "openssh",
				Version: "9.8p1",
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	iniciadas := make(chan struct{}, 2)
	terminado := make(chan error, 1)
	bloqueado := consultorBloqueado{iniciadas: iniciadas}
	config := vuln.Config{
		Timeout:      time.Second,
		MaxBodyBytes: 4096,
	}
	go func() {
		_, err := ejecutarConsultasVuln(ctx, bloqueado, config, consultas, 2)
		terminado <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-iniciadas:

		case <-time.After(2 * time.Second):
			t.Fatal("Error, los trabajadores no han podido comenzar antes del timeout")
		}
	}
	cancel()
	select {
	case err := <-terminado:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Error, el error recibido no era el esperado. %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Error, el pool no terminó a tiempo tras cancelar el contexto")

	}
}
