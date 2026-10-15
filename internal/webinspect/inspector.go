package webinspect

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"

	"golang.org/x/net/html/charset"
)

func validarConfig(config Config) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("El tiempo seleccionado para el timeout no puede ser menor o igual a 0. Se ha introducido %v", config.Timeout)
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > 2*1024*1024 {
		return fmt.Errorf("El numero máximo de bytes ha de estar incluido en el intervalo [1-2097152]. Se ha enviado %d", config.MaxBodyBytes)
	}
	return nil
}

func Inspect(ctx context.Context, direccion string, config Config) Result {
	resultado := Result{
		URL: direccion,
	}
	if err := validarConfig(config); err != nil {
		resultado.Error = err
		return resultado
	}
	if err := ctx.Err(); err != nil {
		resultado.Error = err
		return resultado
	}
	destino, err := url.Parse(direccion)
	if err != nil {
		resultado.Error = err
		return resultado
	}
	if destino.Scheme != "http" && destino.Scheme != "https" {
		resultado.Error = fmt.Errorf("Esquema recibido no valido")
		return resultado
	}
	if destino.Hostname() == "" {
		resultado.Error = fmt.Errorf("El nombre del host se encuentra vacio")
		return resultado
	}
	if destino.User != nil {
		resultado.Error = fmt.Errorf("No se aceptan credenciales dentro de la URL proveida")
		return resultado
	}
	puertoTexto := destino.Port()
	if puertoTexto != "" {
		puerto, err := strconv.Atoi(puertoTexto)
		if err != nil {
			resultado.Error = err
			return resultado
		}
		if puerto < 1 || puerto > 65535 {
			resultado.Error = fmt.Errorf("El puerto proporcionado no está en el intervalo esperado [1-65535]. Puerto: %d", puerto)
			return resultado
		}
	}
	ctxHTTP, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	peticion, err := http.NewRequestWithContext(ctxHTTP, http.MethodGet, destino.String(), nil)
	if err != nil {
		resultado.Error = err
		return resultado
	}
	peticion.Header.Set("User-Agent", "AttackSurfaceAuditor/0.1")
	cliente := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	respuesta, err := cliente.Do(peticion)
	if err != nil {
		resultado.Error = err
		return resultado
	}
	defer respuesta.Body.Close()
	resultado.StatusCode = respuesta.StatusCode
	resultado.Headers = respuesta.Header.Clone()
	readerLimitado := io.LimitReader(respuesta.Body, config.MaxBodyBytes+1)
	cuerpo, err := io.ReadAll(readerLimitado)
	if err != nil {
		resultado.Error = err
		return resultado
	}
	if int64(len(cuerpo)) > config.MaxBodyBytes {
		resultado.Error = fmt.Errorf("El tamaño del cuerpo supera el tamaño maximo permitido. Cuerpo: %d Maximo: %d", int64(len(cuerpo)), config.MaxBodyBytes)
		return resultado
	}
	cabecera := respuesta.Header.Get("Content-Type")
	if cabecera == "" {
		return resultado
	}
	tipo, _, err := mime.ParseMediaType(cabecera)
	if err != nil {
		resultado.Error = err
		return resultado
	}
	if tipo != "text/html" {
		return resultado
	}
	lector := bytes.NewReader(cuerpo)
	lectorUTF8, err := charset.NewReader(lector, cabecera)
	if err != nil {
		resultado.Error = err
		return resultado
	}
	lectorUTF8 = io.LimitReader(lectorUTF8, config.MaxBodyBytes+1)
	cuerpoUTF8, err := io.ReadAll(lectorUTF8)
	if err != nil {
		resultado.Error = err
		return resultado
	}
	if int64(len(cuerpoUTF8)) > config.MaxBodyBytes {
		err = fmt.Errorf("El cuerpo convertido a UTF8 supera el limite")
		resultado.Error = err
		return resultado
	}
	titulo, err := extraerTitulo(cuerpoUTF8)
	if err != nil {
		resultado.Error = err
		return resultado
	}
	resultado.Title = titulo
	return resultado
}
