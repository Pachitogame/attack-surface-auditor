package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func validarConfig(config Config) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("Error, el tiempo limite debe ser mayor a 0. Recibido: %v", config.Timeout)
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > 2*1024*1024 {
		return fmt.Errorf("Error, el numero máximo de bytes no se encuentra en el rango permitido [1-2097152]. Recibido: %d", config.MaxBodyBytes)
	}
	return nil
}

func validarQuery(query Query) error {
	if strings.TrimSpace(query.Product) == "" {
		return fmt.Errorf("Error, el campo de producto esta vacio")
	}
	if strings.TrimSpace(query.Vendor) == "" {
		return fmt.Errorf("Error, el campo del fabricante esta vacio")
	}
	if strings.TrimSpace(query.Version) == "" {
		return fmt.Errorf("Error, el campo de la version esta vacio")
	}
	if query.Product != "openssh" {
		return fmt.Errorf("El producto recibido no coincide con el esperado. Recibido: %q, Esperado: %q", query.Product, "openssh")
	}
	if query.Vendor != "openbsd" {
		return fmt.Errorf("El fabricante recibido no coincide con el esperado. Recibido: %q, Esperado: %q", query.Vendor, "openbsd")
	}
	if !validarVersionOpenSSH(query.Version) {
		return fmt.Errorf("La version del query es invalida. Version: %q", query.Version)
	}
	return nil
}

func (c *Client) Lookup(ctx context.Context, query Query, config Config) ([]CVE, error) {
	err := validarConfig(config)
	if err != nil {
		return nil, err
	}
	err = validarQuery(query)
	if err != nil {
		return nil, err
	}
	err = ctx.Err()
	if err != nil {
		return nil, err
	}
	cpe, err := construirCPE(query)
	if err != nil {
		return nil, err
	}
	urlt := url.URL{
		Scheme: "https",
		Host:   "services.nvd.nist.gov",
		Path:   "/rest/json/cves/2.0",
	}
	parametros := url.Values{}
	parametros.Set("cpeName", cpe)
	urlt.RawQuery = parametros.Encode()
	ctxconsulta, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	return consultarPaginas(ctxconsulta, c.httpClient, urlt, config.MaxBodyBytes, c.limitador)
}

func construirCPE(query Query) (string, error) {
	err := validarQuery(query)
	if err != nil {
		return "", err
	}
	version := strings.Split(query.Version, "p")
	versionBase := version[0]
	actualizacion := "-"
	if len(version) == 2 {
		actualizacion = "p" + version[1]
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:%s:*:*:*:*:*:*", query.Vendor, query.Product, versionBase, actualizacion), nil
}

func consultarPagina(ctx context.Context, cliente *http.Client, direccion string, maxBytes int64, limitador Limitador) (respuestaNVD, error) {
	peticion, err := http.NewRequestWithContext(ctx, http.MethodGet, direccion, nil)
	if err != nil {
		return respuestaNVD{}, err
	}
	peticion.Header.Set("User-Agent", "AttackSurfaceAuditor/0.1")
	peticion.Header.Set("Accept", "application/json")
	err = limitador.Wait(ctx)
	if err != nil {
		return respuestaNVD{}, err
	}
	respuesta, err := cliente.Do(peticion)
	if err != nil {
		return respuestaNVD{}, err
	}
	defer respuesta.Body.Close()
	if respuesta.StatusCode != http.StatusOK {
		return respuestaNVD{}, fmt.Errorf("Error, el estado recibido no es el que se esperaba. Recibido: %d, Esperado: %d", respuesta.StatusCode, http.StatusOK)
	}
	lectorCuerpo := io.LimitReader(respuesta.Body, maxBytes+1)
	cuerpo, err := io.ReadAll(lectorCuerpo)
	if err != nil {
		return respuestaNVD{}, err
	}
	if int64(len(cuerpo)) > maxBytes {
		return respuestaNVD{}, fmt.Errorf("Error, se excede el limite de bytes permitidos de %d. El cuerpo ocupa: %d", maxBytes, int64(len(cuerpo)))
	}
	cabecera := respuesta.Header.Get("Content-Type")
	tipo, _, err := mime.ParseMediaType(cabecera)
	if err != nil {
		return respuestaNVD{}, fmt.Errorf("Content-Type inválido %q: %w", cabecera, err)
	}
	if tipo != "application/json" {
		return respuestaNVD{}, fmt.Errorf("Error, el tipo recibido difiere del esperado. Recibido:%q, Esperado: %q", tipo, "application/json")
	}
	var datos respuestaNVD
	err = json.Unmarshal(cuerpo, &datos)
	if err != nil {
		return respuestaNVD{}, fmt.Errorf("no se pudo interpretar la respuesta JSON de NVD: %w", err)
	}
	err = validarRespuesta(datos)
	if err != nil {
		return respuestaNVD{}, err
	}
	return datos, nil
}
func consultarPaginas(ctx context.Context, cliente *http.Client, direccion url.URL, maxBytes int64, limitador Limitador) ([]CVE, error) {
	parametros := direccion.Query()
	indice := 0
	cves := []CVE{}
	for {
		parametros.Set("startIndex", strconv.Itoa(indice))
		direccion.RawQuery = parametros.Encode()
		datos, err := consultarPagina(ctx, cliente, direccion.String(), maxBytes, limitador)
		if err != nil {
			return nil, err
		}
		if datos.StartIndex != indice {
			return nil, fmt.Errorf("Error, el indice recibido y el esperado difieren. Recibido: %d, Esperado: %d", datos.StartIndex, indice)
		}
		for _, vulnerabilidad := range datos.Vulnerabilities {
			ok := validarID(vulnerabilidad.CVE.ID)
			if !ok {
				return nil, fmt.Errorf("Se ha producido un error. Se ha rechazado el identificador %q", vulnerabilidad.CVE.ID)
			}
			cves = append(cves, CVE{
				ID:          vulnerabilidad.CVE.ID,
				Description: seleccionarDescripcion(vulnerabilidad.CVE.Descriptions),
				URL:         "https://nvd.nist.gov/vuln/detail/" + vulnerabilidad.CVE.ID,
			})
		}
		indice += len(datos.Vulnerabilities)
		if indice == datos.TotalResults {
			break
		}
	}
	return cves, nil
}

func NewClient(limitador Limitador) (*Client, error) {
	if limitador == nil {
		return nil, fmt.Errorf("Error, el limitador recibido como argumento no es valido o es nulo")
	}
	clienteHTTP := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	cliente := Client{
		httpClient: &clienteHTTP,
		limitador:  limitador,
	}
	return &cliente, nil
}
