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
	"strings"

	"golang.org/x/net/html/charset"
)

func validarConfig(config Config) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("El tiempo seleccionado para el timeout no puede ser menor o igual a 0. Se ha introducido %v", config.Timeout)
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > 2*1024*1024 {
		return fmt.Errorf("El numero máximo de bytes ha de estar incluido en el intervalo [1-2097152]. Se ha enviado %d", config.MaxBodyBytes)
	}
	if config.MaxRedirects < 0 || config.MaxRedirects > 10 {
		return fmt.Errorf("El máximo de redirecciones debe estar en el intervalo [0-10], recibido: %d", config.MaxRedirects)
	}
	return nil
}

func Inspect(ctx context.Context, direccion string, config Config) Result {
	resultado := Result{
		URL:       direccion,
		Redirects: []Redirect{},
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
	var errorRedireccion error
	resultado.FinalURL = peticion.URL.String()
	cliente := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if config.MaxRedirects == 0 {
				return http.ErrUseLastResponse
			}
			if len(via) > config.MaxRedirects {
				errorRedireccion = fmt.Errorf("Error, se alcanzó el máximo de %d redirecciones", config.MaxRedirects)
				return http.ErrUseLastResponse
			}
			anterior := via[len(via)-1]
			if err := validarRedireccion(destino, anterior.URL, req.URL); err != nil {
				errorRedireccion = err
				return http.ErrUseLastResponse
			}
			resultado.Redirects = append(resultado.Redirects, Redirect{
				FromURL:    anterior.URL.String(),
				ToURL:      req.URL.String(),
				StatusCode: req.Response.StatusCode,
			})
			resultado.FinalURL = req.URL.String()
			return nil
		},
	}
	respuesta, err := cliente.Do(peticion)
	if respuesta != nil && respuesta.Request != nil {
		resultado.FinalURL = respuesta.Request.URL.String()
	}
	if err != nil {
		resultado.Error = err
		return resultado
	}
	defer respuesta.Body.Close()
	resultado.StatusCode = respuesta.StatusCode
	resultado.Headers = respuesta.Header.Clone()
	if errorRedireccion != nil {
		resultado.Error = errorRedireccion
		return resultado
	}
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
func validarRedireccion(origen, anterior, destino *url.URL) error {
	if destino.Scheme != "http" && destino.Scheme != "https" {
		return fmt.Errorf("Error, esquema de redireccion no permitido: %q", destino.Scheme)
	}
	if destino.Hostname() == "" {
		return fmt.Errorf("Error, la redireccion no contiene el nombre de un host")
	}
	if destino.User != nil {
		return fmt.Errorf("Error, no se permiten credenciales en la URL de redireccion")
	}
	if !strings.EqualFold(origen.Hostname(), destino.Hostname()) {
		return fmt.Errorf("Error, redireccion a otro host bloqueada: %q", destino.Hostname())
	}
	if anterior.Scheme == "https" && destino.Scheme == "http" {
		return fmt.Errorf("Redireccion de HTTPS a HTTP bloqueada")
	}
	if puertoTexto := destino.Port(); puertoTexto != "" {
		puerto, err := strconv.Atoi(puertoTexto)
		if err != nil {
			return fmt.Errorf("Error, puerto de redireccion inválido: %w", err)
		}
		if puerto < 1 || puerto > 65535 {
			return fmt.Errorf("Puerto de redireccion fuera del intervalo [1-65535]: %d", puerto)
		}
	}
	return nil
}
