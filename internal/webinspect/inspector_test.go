package webinspect

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestInspectHTML(t *testing.T) {
	manejador := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err := io.WriteString(w, "<html><head><title>Auditor &amp; Web</title></head></html>")
		if err != nil {
			t.Errorf("Error al escribir el cuerpo HTML: %v", err)
		}
	}
	servidor := httptest.NewServer(http.HandlerFunc(manejador))
	defer servidor.Close()
	config := Config{
		Timeout:      2 * time.Second,
		MaxBodyBytes: 4096,
	}
	resultado := Inspect(context.Background(), servidor.URL, config)
	if resultado.Error != nil {
		t.Fatalf("Se esperaba una inspección sin error; recibido: %v", resultado.Error)
	}
	if resultado.StatusCode != http.StatusOK {
		t.Fatalf("Se esperaba estado %d; recibido: %d", http.StatusOK, resultado.StatusCode)
	}
	if resultado.Title != "Auditor & Web" {
		t.Fatalf("Título esperado: %q; recibido: %q", "Auditor & Web", resultado.Title)
	}
	if resultado.Headers.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type esperado: %q; recibido: %q", "text/html; charset=utf-8", resultado.Headers.Get("Content-Type"))
	}
	if resultado.URL != servidor.URL {
		t.Fatalf("URL esperada: %q; recibida: %q", servidor.URL, resultado.URL)
	}
}

func TestInspectNoSigueRedirecciones(t *testing.T) {
	visitasDestino := make(chan struct{}, 1)
	manejadorDestino := func(w http.ResponseWriter, r *http.Request) {
		select {
		case visitasDestino <- struct{}{}:

		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}
	servidorDestino := httptest.NewServer(http.HandlerFunc(manejadorDestino))
	defer servidorDestino.Close()
	manejadorOrigen := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, servidorDestino.URL, http.StatusFound)
	}
	servidorOrigen := httptest.NewServer(http.HandlerFunc(manejadorOrigen))
	defer servidorOrigen.Close()
	config := Config{
		Timeout:      2 * time.Second,
		MaxBodyBytes: 4096,
	}
	resultado := Inspect(context.Background(), servidorOrigen.URL, config)
	if resultado.Error != nil {
		t.Fatalf("Se esperaba una inspección sin error; recibido: %v", resultado.Error)
	}
	if resultado.StatusCode != http.StatusFound {
		t.Fatalf("Se esperaba estado %d; recibido: %d", http.StatusFound, resultado.StatusCode)
	}
	if resultado.Headers.Get("Location") != servidorDestino.URL {
		t.Fatalf("Content-Type esperado: %q; recibido: %q", servidorDestino.URL, resultado.Headers.Get("Location"))
	}
	if resultado.URL != servidorOrigen.URL {
		t.Fatalf("URL esperada: %q; recibida: %q", servidorOrigen.URL, resultado.URL)
	}
	select {
	case <-visitasDestino:
		t.Fatal("Se visitó un destino que no debia de alcanzarse")
	default:
	}
}

func TestInspectCuerpoExcesivo(t *testing.T) {
	manejador := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err := io.WriteString(w, "ABCDEFGHI")
		if err != nil {
			t.Errorf("error al escribir el cuerpo HTML: %v", err)
		}
	}
	servidor := httptest.NewServer(http.HandlerFunc(manejador))
	defer servidor.Close()
	config := Config{
		Timeout:      2 * time.Second,
		MaxBodyBytes: 8,
	}
	resultado := Inspect(context.Background(), servidor.URL, config)
	if resultado.Error == nil {
		t.Fatalf("Debería haberse producido un error")
	}
	if resultado.StatusCode != http.StatusOK {
		t.Fatalf("El estado no es el esperado. Recibido: %d, Esperado: %d", resultado.StatusCode, http.StatusOK)
	}
	if resultado.Headers.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("La cabecera no se ha conservado, Recibida: %q", resultado.Headers.Get("Content-Type"))
	}
	if resultado.Title != "" {
		t.Fatalf("El título debería de estar vacía y no lo está")
	}
}

func TestInspectorWindows1252(t *testing.T) {
	manejador := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=windows-1252")
		_, err := io.WriteString(w, "<html><head><title>Caf\xe9</title></head></html>")
		if err != nil {
			t.Errorf("error al escribir el cuerpo HTML: %v", err)
		}
	}
	servidor := httptest.NewServer(http.HandlerFunc(manejador))
	defer servidor.Close()
	config := Config{
		Timeout:      2 * time.Second,
		MaxBodyBytes: 4096,
	}
	resultado := Inspect(context.Background(), servidor.URL, config)
	if resultado.Error != nil {
		t.Fatalf("Se esperaba una inspección sin error; recibido: %v", resultado.Error)
	}
	if resultado.Title != "Café" {
		t.Fatalf("Título esperado: %q; recibido: %q", "Café", resultado.Title)
	}
}

func TestInspectRechazaCertificadoNoConfiable(t *testing.T) {
	manejador := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}
	servidor := httptest.NewTLSServer(http.HandlerFunc(manejador))
	defer servidor.Close()
	config := Config{
		Timeout:      2 * time.Second,
		MaxBodyBytes: 4096,
	}
	resultado := Inspect(context.Background(), servidor.URL, config)
	if resultado.Error == nil {
		t.Fatalf("Debería haberse producido un error")
	}
	if resultado.StatusCode != 0 {
		t.Fatalf("Se esperaba que el codigo de estado del resultado fuese 0")
	}
	if resultado.Title != "" {
		t.Fatalf("El titulo deberia de estar vacío, sin embargo se ha recibido: %q", resultado.Title)
	}
}

func TestInspectCanceladoDuranteLectura(t *testing.T) {
	respuestaIniciada := make(chan struct{}, 1)
	resultadoInspect := make(chan Result, 1)
	manejador := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		respuestaIniciada <- struct{}{}
		<-r.Context().Done()
	}
	servidor := httptest.NewServer(http.HandlerFunc(manejador))
	defer servidor.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config := Config{
		Timeout:      10 * time.Second,
		MaxBodyBytes: 4096,
	}
	go func() {
		resultadoInspect <- Inspect(ctx, servidor.URL, config)
	}()
	select {
	case <-respuestaIniciada:

	case <-time.After(4 * time.Second):
		t.Fatal("El servidor no envió la respuesta a tiempo")
	}
	cancel()
	select {
	case resultado := <-resultadoInspect:
		if !errors.Is(resultado.Error, context.Canceled) {
			t.Fatalf("No se recibió el error que esperaba recibirse. Recibido: %v", resultado.Error)
		}
		if resultado.Title != "" {
			t.Fatalf("El resultado debería de estar vacío pero no lo está. Recibido: %q", resultado.Title)
		}
		if resultado.URL != servidor.URL {
			t.Fatalf("La URL del resultado no coincide con la del servidor. Esperada: %q, Recibida: %q", servidor.URL, resultado.URL)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Inspect no terminó a tiempo tras cancelar el contexto")
	}
}
