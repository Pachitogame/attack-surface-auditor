package fingerprint

import (
	"attack-surface-auditor/internal/audit"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestGrabBannerCompleto(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("No se ha podido crear un oyente. Error: %v", err)
	}
	defer listener.Close()
	err = listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		t.Fatalf("Error al intentar establecer el tiempo limite. Error: %v", err)
	}
	textoEsperado := "SSH-2.0-ServidorPrueba\r\n"
	errorServidor := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errorServidor <- err
			return
		}
		defer conn.Close()
		err = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if err != nil {
			errorServidor <- err
			return
		}
		_, err = io.WriteString(conn, textoEsperado)
		errorServidor <- err
	}()
	endpoint := audit.Endpoint{
		DireccionObjetivo: "127.0.0.1",
		Puerto:            listener.Addr().(*net.TCPAddr).Port,
	}
	config := Config{
		Timeout:  2 * time.Second,
		MaxBytes: 1024,
	}
	resultado := Grab(context.Background(), endpoint, config)
	select {
	case errServidor := <-errorServidor:
		if errServidor != nil {
			t.Fatalf("El servidor no pudo enviar el banner: %v", errServidor)
		}
	case <-time.After(4 * time.Second):
		t.Fatalf("El servifor llego a su tiempo limite")
	}
	if resultado.Error != nil {
		t.Fatalf("Se esperaba una captura sin error. Error %v", resultado.Error)
	}
	if string(resultado.Datos) != textoEsperado {
		t.Fatalf("El texto obtenido y el esperado no son equivalentes. Esperado: %q, Recibido: %q", textoEsperado, string(resultado.Datos))
	}
	if resultado.Endpoint != endpoint {
		t.Fatalf("Los endpoint esperado y recibido no coinciden. Esperado: %v, Recibido: %v", endpoint, resultado.Endpoint)
	}
}

func TestGrabLimiteBytes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("No se ha podido crear un oyente. Error: %v", err)
	}
	defer listener.Close()
	err = listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		t.Fatalf("Error al intentar establecer el tiempo limite. Error: %v", err)
	}
	textoEnviado := "ABCDEFGHIJ"
	textoEsperado := "ABCD"
	errorServidor := make(chan error, 1)
	liberarServidor := make(chan struct{})
	defer close(liberarServidor)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errorServidor <- err
			return
		}
		defer conn.Close()
		err = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if err != nil {
			errorServidor <- err
			return
		}
		_, err = io.WriteString(conn, textoEnviado)
		errorServidor <- err
		if err != nil {
			return
		}
		<-liberarServidor
	}()
	endpoint := audit.Endpoint{
		DireccionObjetivo: "127.0.0.1",
		Puerto:            listener.Addr().(*net.TCPAddr).Port,
	}
	config := Config{
		Timeout:  2 * time.Second,
		MaxBytes: 4,
	}
	resultado := Grab(context.Background(), endpoint, config)
	select {
	case errServidor := <-errorServidor:
		if errServidor != nil {
			t.Fatalf("El servidor no pudo enviar el banner: %v", errServidor)
		}
	case <-time.After(4 * time.Second):
		t.Fatalf("El servifor llego a su tiempo limite")
	}
	if resultado.Error != nil {
		t.Fatalf("Se esperaba una captura sin error. Error %v", resultado.Error)
	}
	if string(resultado.Datos) != textoEsperado {
		t.Fatalf("El texto obtenido y el esperado no son equivalentes. Esperado: %q, Recibido: %q", textoEsperado, string(resultado.Datos))
	}
	if resultado.Endpoint != endpoint {
		t.Fatalf("Los endpoint esperado y recibido no coinciden. Esperado: %v, Recibido: %v", endpoint, resultado.Endpoint)
	}
}

func TestGrabCanceladoDuranteLectura(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("No se ha podido crear un oyente. Error: %v", err)
	}
	defer listener.Close()
	err = listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		t.Fatalf("Error al intentar establecer el tiempo limite. Error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conexionAceptada := make(chan error, 1)
	liberarServidor := make(chan struct{})
	resultadoGrab := make(chan BannerResult, 1)
	defer close(liberarServidor)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			conexionAceptada <- err
			return
		}
		defer conn.Close()
		conexionAceptada <- nil
		<-liberarServidor
	}()
	endpoint := audit.Endpoint{
		DireccionObjetivo: "127.0.0.1",
		Puerto:            listener.Addr().(*net.TCPAddr).Port,
	}
	config := Config{
		Timeout:  10 * time.Second,
		MaxBytes: 1024,
	}
	go func() {
		resultadoGrab <- Grab(ctx, endpoint, config)
	}()
	select {
	case errServidor := <-conexionAceptada:
		if errServidor != nil {
			t.Fatalf("El servidor no pudo aceptar la conexion: %v", errServidor)
		}
	case <-time.After(4 * time.Second):
		t.Fatalf("El servidor llego a su tiempo limite")
	}
	cancel()
	select {
	case resultado := <-resultadoGrab:
		if !errors.Is(resultado.Error, context.Canceled) {
			t.Fatalf("se esperaba context.Canceled; se recibió: %v", resultado.Error)
		}
		if len(resultado.Datos) != 0 {
			t.Fatalf("Ha llegado algo como resultado, no debería haber llegado nada")
		}
		if resultado.Endpoint != endpoint {
			t.Fatalf("Los endpoint esperado y recibido no coinciden. Esperado: %v, Recibido: %v", endpoint, resultado.Endpoint)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Grab no terminó a tiempo tras cancelar el contexto")
	}
}

func TestGrabSSHNoEsperaCierre(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("No se ha podido crear un oyente. Error: %v", err)
	}
	defer listener.Close()
	err = listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		t.Fatalf("Error al intentar establecer el tiempo limite. Error: %v", err)
	}
	textoEsperado := "SSH-2.0-ServidorPrueba\r\n"
	errorServidor := make(chan error, 1)
	liberarServidor := make(chan struct{})
	defer close(liberarServidor)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errorServidor <- err
			return
		}
		defer conn.Close()
		err = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if err != nil {
			errorServidor <- err
			return
		}
		_, err = io.WriteString(conn, textoEsperado)
		errorServidor <- err
		if err != nil {
			return
		}
		<-liberarServidor
	}()
	endpoint := audit.Endpoint{
		DireccionObjetivo: "127.0.0.1",
		Puerto:            listener.Addr().(*net.TCPAddr).Port,
	}
	config := Config{
		Timeout:  2 * time.Second,
		MaxBytes: 1024,
	}
	resultado := Grab(context.Background(), endpoint, config)
	select {
	case errServidor := <-errorServidor:
		if errServidor != nil {
			t.Fatalf("El servidor no pudo enviar el banner: %v", errServidor)
		}
	case <-time.After(4 * time.Second):
		t.Fatalf("El servifor llego a su tiempo limite")
	}
	if resultado.Error != nil {
		t.Fatalf("Se esperaba una captura sin error. Error %v", resultado.Error)
	}
	if string(resultado.Datos) != textoEsperado {
		t.Fatalf("El texto obtenido y el esperado no son equivalentes. Esperado: %q, Recibido: %q", textoEsperado, string(resultado.Datos))
	}
	if resultado.Endpoint != endpoint {
		t.Fatalf("Los endpoint esperado y recibido no coinciden. Esperado: %v, Recibido: %v", endpoint, resultado.Endpoint)
	}
}
