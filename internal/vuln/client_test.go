package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type limitadorSinEspera struct {
}
type limitadorContador struct {
	llamadas int
}

func (l *limitadorContador) Wait(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	l.llamadas++
	return nil
}
func (limitadorSinEspera) Wait(ctx context.Context) error {
	return ctx.Err()
}
func TestConstruirCPEOpenSSH(t *testing.T) {
	query := Query{
		Vendor:  "openbsd",
		Product: "openssh",
		Version: "9.6p1",
	}
	cpe, err := construirCPE(query)
	if err != nil {
		t.Fatalf("Se ha producido un error en la construccion del CPE, %v", err)
	}
	if cpe != "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*" {
		t.Fatalf("El CPE recibido y el esperado son distintos. Recibido: %q, Esperado: %q", cpe, "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*")
	}
}
func TestConsultarPaginaJSON(t *testing.T) {
	manejador := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		cuerpo := `{
		"resultsPerPage": 1,
		"startIndex": 0,
		"totalResults": 1,
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2024-1234",
					"descriptions": [
						{"lang": "en", "value": "Descripcion de prueba"}
					]
				}
			}
		]
	}`
		_, err := io.WriteString(w, cuerpo)
		if err != nil {
			t.Errorf("Error al escribir la respuesta en el cuerpo. Error: %v", err)
		}
	}
	servidor := httptest.NewServer(http.HandlerFunc(manejador))
	defer servidor.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	respuesta, err := consultarPagina(ctx, servidor.Client(), servidor.URL, 4096, limitadorSinEspera{})
	if err != nil {
		t.Fatalf("Error al consultar la pagina. Error: %v", err)
	}
	if respuesta.ResultsPerPage != 1 {
		t.Fatalf("Error, se esperaba 1 resultado por pagina, se han recibido %d", respuesta.ResultsPerPage)
	}
	if respuesta.StartIndex != 0 {
		t.Fatalf("Error, se esperaba un indice inicial de 0, se ha recibido %d", respuesta.StartIndex)
	}
	if respuesta.TotalResults != 1 {
		t.Fatalf("Error, se esperaba una cantidad de resultados totales de 1, se ha recibido %d", respuesta.TotalResults)
	}
	if len(respuesta.Vulnerabilities) != 1 {
		t.Fatalf("Error, se esperaba recibir 1 vulnerabilidad, se ha recibido %d", len(respuesta.Vulnerabilities))
	}
	cve := respuesta.Vulnerabilities[0].CVE
	if cve.ID != "CVE-2024-1234" {
		t.Errorf("Error, se esperaba que el ID fuese %q, sin embargo se recibió %q", "CVE-2024-1234", cve.ID)
	}
	if len(cve.Descriptions) != 1 {
		t.Fatalf("Error, se esperaba que la longitud de la lista de descripciones fuese 1, sin embargo se recibió %d", len(cve.Descriptions))
	}
	if cve.Descriptions[0].Lang != "en" {
		t.Errorf("Error, se esperaba que el Lang fuera %q, sin embargo se recibió %q", "en", cve.Descriptions[0].Lang)
	}
	if cve.Descriptions[0].Value != "Descripcion de prueba" {
		t.Errorf("Error, se esperaba que el valor fuera %q, sin embargo se recibió %q", "Descripcion de prueba", cve.Descriptions[0].Value)
	}
}

func TestConsultarPaginaJSONInvalido(t *testing.T) {
	manejador := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		cuerpo := `{"totalResults":`
		_, err := io.WriteString(w, cuerpo)
		if err != nil {
			t.Errorf("Error al escribir la respuesta en el cuerpo. Error: %v", err)
		}
	}
	servidor := httptest.NewServer(http.HandlerFunc(manejador))
	defer servidor.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := consultarPagina(ctx, servidor.Client(), servidor.URL, 4096, limitadorSinEspera{})
	if err == nil {
		t.Fatal("Error, se esperaba un fallo, sin embargo no se recibió nada")
	}
	var errSintaxis *json.SyntaxError
	if !errors.As(err, &errSintaxis) {
		t.Errorf("se esperaba un error de sintaxis JSON; recibido: %T: %v", err, err)
	}
}
func TestConsultarPaginas(t *testing.T) {
	manejador := func(w http.ResponseWriter, r *http.Request) {
		indice := r.URL.Query().Get("startIndex")
		var datos respuestaNVD
		switch indice {
		case "0":
			datos = respuestaNVD{
				ResultsPerPage: 2,
				StartIndex:     0,
				TotalResults:   3,
				Vulnerabilities: []vulnerabilidadNVD{
					{CVE: cveNVD{ID: "CVE-2024-1234"}},
					{CVE: cveNVD{ID: "CVE-2024-1235"}},
				},
			}
		case "2":
			datos = respuestaNVD{
				ResultsPerPage: 1,
				StartIndex:     2,
				TotalResults:   3,
				Vulnerabilities: []vulnerabilidadNVD{
					{CVE: cveNVD{ID: "CVE-2024-1236"}},
				},
			}
		default:
			t.Errorf("Error, el indice solicitado es inesperdo, %q", indice)
			http.Error(w, "Error, indice inesperado", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(datos); err != nil {
			t.Errorf("Error al enviar la pagina: %v", err)
		}
	}
	servidor := httptest.NewServer(http.HandlerFunc(manejador))
	defer servidor.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	direccion, err := url.Parse(servidor.URL)
	if err != nil {
		t.Fatalf("Error, no se ha podido parsear la URL. %v", err)
	}
	limitador := &limitadorContador{}
	cves, err := consultarPaginas(ctx, servidor.Client(), *direccion, 4096, limitador)
	if err != nil {
		t.Fatalf("Error al consultar las páginas. %v", err)
	}
	if limitador.llamadas != 2 {
		t.Errorf("Error, se esperaban 2 llamadas en el limitador, sin embargo se han recibido %d", limitador.llamadas)
	}
	if len(cves) != 3 {
		t.Fatalf("Se esperaba que la cantidad de CVEs fuera 3, sin embargo se recibió %d", len(cves))
	}
	idsEsperados := []string{"CVE-2024-1234", "CVE-2024-1235", "CVE-2024-1236"}
	for i, cve := range cves {
		if cve.ID != idsEsperados[i] {
			t.Errorf("Error en la posicion %d, se esperaba recibir %q, sin embargo se recibió %q", i, idsEsperados[i], cve.ID)
		}
	}
}
