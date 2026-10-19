package main

import (
	"attack-surface-auditor/internal/audit"
	"attack-surface-auditor/internal/vuln"
	"attack-surface-auditor/internal/webinspect"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestImprimirCVE(t *testing.T) {
	var salida bytes.Buffer
	cve := vuln.CVE{
		ID:          "CVE-2024-1234",
		Description: "Primera linea\nSegunda linea",
		URL:         "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
	}
	imprimirCVE(&salida, cve)
	texto := salida.String()
	if !strings.Contains(texto, "[!] CVE candidato: "+cve.ID+"\n") {
		t.Errorf("Error, no aparece el identificador esperado, salida: %q", texto)
	}
	if !strings.Contains(texto, "    Enlace: "+cve.URL+"\n") {
		t.Errorf("Error, no aparece el enlace completo sin comilla, salida: %q", texto)
	}
	if !strings.Contains(texto, `Descripcion: "Primera linea\nSegunda linea"`) {
		t.Errorf("Error, la descripcion no conserva el salto de linea escapado, salida: %q", texto)
	}
}

func TestImprimirResultadoWebSinRespuesta(t *testing.T) {
	var salida bytes.Buffer
	resultado := webinspect.Result{
		URL:   "https://127.0.0.1:443/",
		Error: errors.New("fallo de conexion"),
	}

	imprimirResultadoWeb(&salida, resultado)
	texto := salida.String()
	if !strings.Contains(texto, resultado.URL) {
		t.Errorf("No aparece la URL; salida: %q", texto)
	}
	if strings.Contains(texto, "Estado HTTP:") {
		t.Errorf("No debe aparecer un estado HTTP sin respuesta; salida: %q", texto)
	}
	if !strings.Contains(texto, `Error: "fallo de conexion"`) {
		t.Errorf("No aparece el error esperado; salida: %q", texto)
	}
	if strings.Contains(texto, "Titulo:") {
		t.Errorf("No debe aparecer un titulo vacio; salida: %q", texto)
	}
}
func TestImprimirResultadoPuertoErrores(t *testing.T) {
	casos := []struct {
		nombre       string
		estado       audit.EstadoPuerto
		muestraError bool
	}{
		{"cerrado", audit.EstadoCerrado, false},
		{"timeout", audit.EstadoTimeout, true},
		{"indeterminado", audit.EstadoIndeterminado, true},
	}
	for _, caso := range casos {
		t.Run(caso.nombre, func(t *testing.T) {
			var salida bytes.Buffer
			resultado := audit.ScanResult{
				EndpointExaminado: audit.Endpoint{
					DireccionObjetivo: "127.0.0.1",
					Puerto:            22,
				},
				Resultado:  caso.estado,
				DatosError: errors.New("error de prueba"),
			}
			imprimirResultadoPuerto(&salida, resultado)
			texto := salida.String()
			if !strings.Contains(texto, "[TCP] 127.0.0.1:22 | "+caso.estado.String()) {
				t.Errorf("Falta el endpoint o su estado, salida: %q", texto)
			}
			muestraError := strings.Contains(texto, `Error: "error de prueba"`)
			if muestraError != caso.muestraError {
				t.Errorf("Mostrar error: esperado: %t, recibido: %t, salida: %q", caso.muestraError, muestraError, texto)
			}
		})
	}
}
func TestImprimirResultadoWebConRedireccion(t *testing.T) {
	var salida bytes.Buffer
	resultado := webinspect.Result{
		URL:        "http://127.0.0.1/",
		FinalURL:   "http://127.0.0.1/final",
		StatusCode: 200,
		Title:      "Destino final",
		Redirects: []webinspect.Redirect{
			{
				FromURL:    "http://127.0.0.1/",
				ToURL:      "http://127.0.0.1/final",
				StatusCode: 302,
			},
		},
	}

	imprimirResultadoWeb(&salida, resultado)

	esperados := []string{
		`[WEB] "http://127.0.0.1/"`,
		`Salto 1: HTTP 302 | "http://127.0.0.1/" -> "http://127.0.0.1/final"`,
		`URL final: "http://127.0.0.1/final"`,
		"Estado HTTP: 200",
		`Titulo: "Destino final"`,
	}

	for _, esperado := range esperados {
		if !strings.Contains(salida.String(), esperado) {
			t.Errorf("Falta el contenido %q; salida: %q",
				esperado, salida.String())
		}
	}
}
