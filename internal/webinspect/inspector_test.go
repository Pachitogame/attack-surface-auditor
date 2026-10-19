package webinspect

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestInspectSigueRedireccion(t *testing.T) {
	manejador := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if _, err := io.WriteString(w, "<title>Destino final</title>"); err != nil {
				t.Errorf("Error al escribir el HTML: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}
	servidor := httptest.NewServer(http.HandlerFunc(manejador))
	defer servidor.Close()
	config := Config{
		Timeout:      2 * time.Second,
		MaxBodyBytes: 4096,
		MaxRedirects: 1,
	}
	resultado := Inspect(context.Background(), servidor.URL, config)
	if resultado.Error != nil {
		t.Fatalf("Error, se esperaba una isnpeccion sin error, sin embargo se recibió: %v", resultado.Error)
	}
	if resultado.StatusCode != http.StatusOK {
		t.Errorf("Error, se esperaba recibir el estado: %d, sin embargo se recibió el estado: %d", http.StatusOK, resultado.StatusCode)
	}
	if resultado.Title != "Destino final" {
		t.Errorf("Error, se esperaba recibir el titulo: %q, sin embargo se recibió: %q", "Destino final", resultado.Title)
	}
	if resultado.URL != servidor.URL {
		t.Errorf("Error, se esperaba recibir la URL: %q, sin embargo se recibió: %q", servidor.URL, resultado.URL)
	}
	if resultado.FinalURL != servidor.URL+"/final" {
		t.Errorf("Error, se esperaba recibir la URL final: %q, sin embargo se recibió: %q", servidor.URL+"/final", resultado.FinalURL)
	}
	if len(resultado.Redirects) != 1 {
		t.Fatalf("Error, se esperaba realizar 1 salto, sin embargo se realizaron: %d", len(resultado.Redirects))
	}
	salto := resultado.Redirects[0]
	if salto.FromURL != servidor.URL {
		t.Errorf("Error, se esperaba recibir el origen: %q, sin embargo se recibió: %q", servidor.URL, salto.FromURL)
	}
	if salto.ToURL != servidor.URL+"/final" {
		t.Errorf("Error, se esperaba recibir el destino: %q; sin embargo se recibió: %q", servidor.URL+"/final", salto.ToURL)
	}
	if salto.StatusCode != http.StatusFound {
		t.Errorf("Error, se esperaba recibir el estado de salto: %d; sin embargo se recibió: %d", http.StatusFound, salto.StatusCode)
	}
}

func TestInspectLimitaRedirecciones(t *testing.T) {
	visitasFinal := make(chan struct{}, 1)
	manejador := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/intermedio", http.StatusFound)
		case "/intermedio":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			select {
			case visitasFinal <- struct{}{}:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}
	servidor := httptest.NewServer(http.HandlerFunc(manejador))
	defer servidor.Close()
	config := Config{
		Timeout:      2 * time.Second,
		MaxBodyBytes: 4096,
		MaxRedirects: 1,
	}
	resultado := Inspect(context.Background(), servidor.URL, config)
	if resultado.Error == nil {
		t.Fatal("Error, se esperaba recibir un error por alcanzar el limite de redirecciones")
	}
	if len(resultado.Redirects) != 1 {
		t.Fatalf("Error, se esperaba registrar un salto, sin embargo se registró: %d", len(resultado.Redirects))
	}
	if resultado.FinalURL != servidor.URL+"/intermedio" {
		t.Errorf("Error, se esperaba recibir la URL final: %q, sin embargo se recibió: %q", servidor.URL+"/intermedio", resultado.FinalURL)
	}
	if resultado.StatusCode != http.StatusFound {
		t.Errorf("Error, se esperaba recibir el estado: %d, sin embargo se recibió: %d", http.StatusFound, resultado.StatusCode)
	}
	if resultado.Headers.Get("Location") != "/final" {
		t.Errorf("Error, se esperaba recibir la localización: %q, sin embargo se recibió: %q", "/final", resultado.Headers.Get("Location"))
	}
	select {
	case <-visitasFinal:
		t.Fatal("Error, se visitó un destino que debía quedar bloqueado")
	default:
	}
}

func TestInspectBloqueaCambioDeHost(t *testing.T) {
	visitasFinal := make(chan struct{}, 1)

	manejador := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			select {
			case visitasFinal <- struct{}{}:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		hostDestino := strings.Replace(r.Host, "127.0.0.1", "localhost", 1)
		http.Redirect(w, r, "http://"+hostDestino+"/final", http.StatusFound)
	}

	servidor := httptest.NewServer(http.HandlerFunc(manejador))
	defer servidor.Close()

	config := Config{
		Timeout:      2 * time.Second,
		MaxBodyBytes: 4096,
		MaxRedirects: 5,
	}

	resultado := Inspect(context.Background(), servidor.URL, config)

	if resultado.Error == nil {
		t.Fatal("Se esperaba un error por cambio de host")
	}
	if !strings.Contains(resultado.Error.Error(), "otro host") {
		t.Fatalf("Se esperaba un error por cambio de host; recibido: %v",
			resultado.Error)
	}
	if len(resultado.Redirects) != 0 {
		t.Errorf("No se esperaban saltos autorizados; recibidos: %d",
			len(resultado.Redirects))
	}
	if resultado.FinalURL != servidor.URL {
		t.Errorf("URL final esperada: %q; recibida: %q",
			servidor.URL, resultado.FinalURL)
	}
	if resultado.StatusCode != http.StatusFound {
		t.Errorf("Estado esperado: %d; recibido: %d",
			http.StatusFound, resultado.StatusCode)
	}

	select {
	case <-visitasFinal:
		t.Fatal("Se visitó el destino con otro nombre de host")
	default:
	}
}
func TestValidarRedireccionEsquemas(t *testing.T) {
	casos := []struct {
		nombre      string
		anterior    string
		destino     string
		esperaError bool
	}{
		{"http a https permitido", "http", "https", false},
		{"https a https permitido", "https", "https", false},
		{"https a http bloqueado", "https", "http", true},
	}

	for _, caso := range casos {
		t.Run(caso.nombre, func(t *testing.T) {
			origen := &url.URL{
				Scheme: "http",
				Host:   "127.0.0.1",
			}
			anterior := &url.URL{
				Scheme: caso.anterior,
				Host:   "127.0.0.1",
			}
			destino := &url.URL{
				Scheme: caso.destino,
				Host:   "127.0.0.1",
			}

			err := validarRedireccion(origen, anterior, destino)

			if (err != nil) != caso.esperaError {
				t.Fatalf("Se esperaba error: %t; recibido: %v",
					caso.esperaError, err)
			}
			if caso.esperaError && !strings.Contains(err.Error(), "HTTPS a HTTP") {
				t.Errorf("Se esperaba un error por bajar de HTTPS a HTTP; recibido: %v", err)
			}
		})
	}
}
func TestInspectTimeoutTrasRedireccion(t *testing.T) {
	destinoVisitado := make(chan struct{}, 1)

	manejador := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			destinoVisitado <- struct{}{}
			<-r.Context().Done()
		default:
			http.NotFound(w, r)
		}
	}

	servidor := httptest.NewServer(http.HandlerFunc(manejador))
	defer servidor.Close()

	config := Config{
		Timeout:      time.Second,
		MaxBodyBytes: 4096,
		MaxRedirects: 1,
	}

	resultado := Inspect(context.Background(), servidor.URL, config)

	if !errors.Is(resultado.Error, context.DeadlineExceeded) {
		t.Fatalf("Se esperaba context.DeadlineExceeded; recibido: %v",
			resultado.Error)
	}

	select {
	case <-destinoVisitado:
	default:
		t.Fatal("La petición no llegó al destino de la redirección")
	}

	if len(resultado.Redirects) != 1 {
		t.Errorf("Se esperaba conservar un salto; recibidos: %d",
			len(resultado.Redirects))
	}
	if resultado.FinalURL != servidor.URL+"/final" {
		t.Errorf("URL final esperada: %q; recibida: %q",
			servidor.URL+"/final", resultado.FinalURL)
	}
}
