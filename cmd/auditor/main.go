package main

import (
	"attack-surface-auditor/internal/audit"
	"attack-surface-auditor/internal/fingerprint"
	"attack-surface-auditor/internal/report"
	"attack-surface-auditor/internal/scanner"
	"attack-surface-auditor/internal/vuln"
	"attack-surface-auditor/internal/webinspect"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"time"
)

func main() {
	os.Exit(run())
}

func run() int {
	host := flag.String("host", "", "Dirección IP o nombre de host que se va a auditar")
	puertosTexto := flag.String("ports", "80", "Puertos TCP separados por comas o rangos inclusivos (ejemplo: 22,80,8000-8003)")
	trabajadores := flag.Int("workers", 10, "Número máximo de trabajadores concurrentes")
	timeout := flag.Duration("timeout", time.Second, "Tiempo máximo de espera para cada escaneo")
	capturarBanner := flag.Bool("banner", false, "Habilita la captura y la identificación")
	bannerTimeout := flag.Duration("banner-timeout", 2*time.Second, "Limita el tiempo total por captura")
	bannerMaxBytes := flag.Int("banner-max-bytes", 4096, "Limita los bytes recibidos por destino")
	inspeccionarWeb := flag.Bool("web", false, "Habilita la inspección HTTP en el puerto 80 y HTTPS en el puerto 443")
	webTimeout := flag.Duration("web-timeout", 3*time.Second, "Tiempo máximo por inspección web, incluida la lectura del cuerpo")
	webMaxBytes := flag.Int64("web-max-bytes", 2*1024*1024, "Máximo de bytes del cuerpo antes y después de convertirlo a UTF-8")
	webMaxRedirects := flag.Int("web-max-redirects", 5, "Máximo de redirecciones web [0-10]; 0 desactiva el seguimiento")
	consultarVuln := flag.Bool("vuln", false, "Consulta posibles CVEs para los servicios identificados")
	vulnTimeout := flag.Duration("vuln-timeout", 60*time.Second, "Tiempo máximo por consulta de vulnerabilidades, incluidas esperas y páginas")
	rutaReporte := flag.String("output", "", "Ruta del informe JSON; no sobrescribe archivos existentes")
	soloAbiertos := flag.Bool("open", false, "Muestra solo los puertos abiertos en la consola, el informe JSON conserva todos los resultados")
	flag.Parse()
	if *consultarVuln {
		if *vulnTimeout <= 0 {
			fmt.Fprintf(os.Stderr, "El timeout debe ser mayor que 0, se ha recibido %v\n", *vulnTimeout)
			return 1
		}
		if !*capturarBanner {
			fmt.Fprintf(os.Stderr, "La captura de banner ha de estar activada\n")
			return 1
		}
	}
	if *inspeccionarWeb {
		if *webMaxRedirects < 0 || *webMaxRedirects > 10 {
			fmt.Fprintf(os.Stderr, "El máximo de redirecciones debe estar en el intervalo [0-10], Recibido: %d", *webTimeout)
			return 1
		}
		if *webTimeout <= 0 {
			fmt.Fprintf(os.Stderr, "El tiempo limite debe ser mayor que 0. Tiempo recibido: %v\n", *webTimeout)
			return 1
		}
		if *webMaxBytes < 1 || *webMaxBytes > 2*1024*1024 {
			fmt.Fprintf(os.Stderr, "El numero máximo de bytes no está dentro del intervalo permitido. Permitido: [1-2097152], Recibido: %d\n", *webMaxBytes)
			return 1
		}
	}
	if *capturarBanner {
		if *bannerTimeout <= 0 {
			fmt.Fprintf(os.Stderr, "El tiempo limite debe ser mayor que 0. Tiempo recibido: %v\n", *bannerTimeout)
			return 1
		}
		if *bannerMaxBytes < 1 || *bannerMaxBytes > 65536 {
			fmt.Fprintf(os.Stderr, "El numero máximo de bytes no está dentro del intervalo permitido. Permitido: [1-65536], Recibido: %d\n", *bannerMaxBytes)
			return 1
		}
	}
	var clienteVuln *vuln.Client
	if *consultarVuln {
		limitador, err := vuln.NewLimiter(7 * time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error al crear el limitador: %v\n", err)
			return 1
		}
		clienteVuln, err = vuln.NewClient(limitador)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error al crear el cliente de vulnerabilidades: %v\n", err)
			return 1
		}
	}
	puertos, err := parsePorts(*puertosTexto)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al parsear los puertos: %v\n", err)
		return 1
	}
	endpoints := make([]audit.Endpoint, len(puertos))
	for i, puerto := range puertos {
		endpoints[i] = audit.Endpoint{
			DireccionObjetivo: *host,
			Puerto:            puerto,
		}
	}
	config := audit.ScanConfig{
		NMaxTrabajadores: *trabajadores,
		TiempoLimite:     *timeout,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var completados atomic.Int64
	fmt.Fprintf(os.Stderr, "Iniciando el escaneo de %d puertos...\n", len(endpoints))
	observar := func(resultado audit.ScanResult) {
		completados.Add(1)
		if !*soloAbiertos || resultado.Resultado == audit.EstadoAbierto {
			imprimirResultadoPuerto(os.Stdout, resultado)
		}
	}
	detenerProgreso := make(chan struct{})
	progresoTerminado := make(chan struct{})
	go func() {
		defer close(progresoTerminado)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		mostrarProgreso(os.Stderr, &completados, len(endpoints), ticker.C, detenerProgreso)
	}()
	informe, err := scanner.ScanWithObserver(ctx, config, endpoints, observar)
	close(detenerProgreso)
	<-progresoTerminado
	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "Escaneo interrumpido: %d/%d puertos examinados\n", completados.Load(), len(endpoints))
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "Escaneo finalizado con error: %d/%d puertos examinados\n", completados.Load(), len(endpoints))
	} else {
		fmt.Fprintf(os.Stderr, "Escaneo terminado: %d/%d puertos examinados\n", completados.Load(), len(endpoints))
	}
	configBanner := fingerprint.Config{
		Timeout:  *bannerTimeout,
		MaxBytes: *bannerMaxBytes,
	}
	configWeb := webinspect.Config{
		Timeout:      *webTimeout,
		MaxBodyBytes: *webMaxBytes,
		MaxRedirects: *webMaxRedirects,
	}
	configVuln := vuln.Config{
		Timeout:      *vulnTimeout,
		MaxBodyBytes: 2 * 1024 * 1024,
	}
	informeJSON := report.Report{
		VersionFormato: "1.0",
		Objetivo:       *host,
		Estado:         "completada",
		Endpoints:      []report.EndpointReport{},
	}
	indicesReporte := make(map[audit.Endpoint]int)
	falloConsulta := false
	consultasVuln := []consultaVuln{}
	for _, resultado := range informe {
		entrada := report.EndpointReport{
			Endpoint: resultado.EndpointExaminado,
			Estado:   resultado.Resultado.String(),
		}
		if resultado.DatosError != nil {
			entrada.ErrorEscaneo = resultado.DatosError.Error()
		}
		indice := len(informeJSON.Endpoints)
		informeJSON.Endpoints = append(informeJSON.Endpoints, entrada)
		indicesReporte[resultado.EndpointExaminado] = indice
		if *inspeccionarWeb && resultado.Resultado == audit.EstadoAbierto {
			esquema := ""
			switch resultado.EndpointExaminado.Puerto {
			case 80:
				esquema = "http"
			case 443:
				esquema = "https"
			}
			if esquema != "" {
				direccionWeb := url.URL{
					Scheme: esquema,
					Host:   net.JoinHostPort(resultado.EndpointExaminado.DireccionObjetivo, strconv.Itoa(resultado.EndpointExaminado.Puerto)),
					Path:   "/",
				}
				if ctx.Err() == nil {
					inspeccion := webinspect.Inspect(ctx, direccionWeb.String(), configWeb)
					informeJSON.Endpoints[indice].Web = &report.WebReport{
						URL:        inspeccion.URL,
						FinalURL:   inspeccion.FinalURL,
						StatusCode: inspeccion.StatusCode,
						Headers:    inspeccion.Headers,
						Title:      inspeccion.Title,
					}
					for _, salto := range inspeccion.Redirects {
						informeJSON.Endpoints[indice].Web.Redirects = append(informeJSON.Endpoints[indice].Web.Redirects, report.RedirectReport{
							FromURL:    salto.FromURL,
							ToURL:      salto.ToURL,
							StatusCode: salto.StatusCode,
						})
					}
					imprimirResultadoWeb(os.Stdout, inspeccion)
					if inspeccion.Error != nil {
						informeJSON.Endpoints[indice].Web.Error = inspeccion.Error.Error()
					}
				}
			}
		}
		if *capturarBanner && resultado.Resultado == audit.EstadoAbierto {
			if ctx.Err() != nil {
				continue
			}
			banner := fingerprint.Grab(ctx, resultado.EndpointExaminado, configBanner)
			informeJSON.Endpoints[indice].Banner = &report.BannerReport{
				Datos: banner.Datos,
			}
			imprimirBanner(os.Stdout, resultado.EndpointExaminado, banner.Datos, banner.Error)
			if banner.Error != nil {
				informeJSON.Endpoints[indice].Banner.Error = banner.Error.Error()
			}
			info, ok := fingerprint.Identify(banner.Datos)
			if ok {
				fmt.Printf("         Servicio: %q\n", info.Servicio)
				fmt.Printf("         Protocolo: %q\n", info.VersionProtocolo)
				fmt.Printf("         Software: %q\n", info.Software)
				informeJSON.Endpoints[indice].Banner.Servicio = &info
				if *consultarVuln && ctx.Err() == nil {
					query, compatible := vuln.QueryFromService(info)
					if compatible {
						consultasVuln = append(consultasVuln, consultaVuln{
							Endpoint: resultado.EndpointExaminado,
							Query:    query,
						})
						informeJSON.Endpoints[indice].Vuln = &report.VulnReport{
							Query:  query,
							Estado: "pendiente",
							CVEs:   []vuln.CVE{},
						}
					} else {
						fmt.Println("Consulta de CVEs no disponible para este software")
					}
				}
			} else {
				fmt.Println("         Servicio no identificado con los datos recibidos")
			}
		}
	}
	if *consultarVuln && len(consultasVuln) > 0 && ctx.Err() == nil {
		resultadosVuln, errPool := ejecutarConsultasVuln(ctx, clienteVuln, configVuln, consultasVuln, 2)
		if errPool != nil {
			fmt.Fprintf(os.Stderr, "Se ha producido un error al ejecutar las consultas de vulnerabilidades. %v\n", errPool)
			falloConsulta = true
		}
		for _, resultado := range resultadosVuln {
			indice, existe := indicesReporte[resultado.Endpoint]
			if !existe {
				fmt.Fprintf(os.Stderr, "Resultado de CVEs para un endpoint desconocido: %+v\n", resultado.Endpoint)
				falloConsulta = true
				continue
			}
			registroVuln := informeJSON.Endpoints[indice].Vuln
			fmt.Printf("Direccion: %q, Puerto: %d\n", resultado.Endpoint.DireccionObjetivo, resultado.Endpoint.Puerto)
			if resultado.Error != nil {
				fmt.Fprintf(os.Stderr, "Error al consultar CVEs para %q puerto %d: %v\n", resultado.Endpoint.DireccionObjetivo, resultado.Endpoint.Puerto, resultado.Error)
				falloConsulta = true
				registroVuln.Error = resultado.Error.Error()
				registroVuln.Estado = "fallida"
				if errors.Is(resultado.Error, context.Canceled) {
					registroVuln.Estado = "cancelada"
				}
				continue
			}
			registroVuln.Estado = "completada"
			registroVuln.CVEs = append(registroVuln.CVEs, resultado.CVEs...)
			if len(resultado.CVEs) == 0 {
				fmt.Println("La consulta no devolvió CVEs candidatos")
			} else {
				for _, cve := range resultado.CVEs {
					imprimirCVE(os.Stdout, cve)
				}
			}
		}
	}
	for _, endpoint := range informeJSON.Endpoints {
		puntero := endpoint.Vuln
		if puntero == nil || puntero.Estado != "pendiente" {
			continue
		}
		if ctx.Err() != nil {
			puntero.Estado = "cancelada"
			puntero.Error = ctx.Err().Error()
		} else {
			puntero.Estado = "fallida"
			puntero.Error = "La consulta no produjo un resultado"
			falloConsulta = true
		}
	}
	informeJSON.GeneradoEn = time.Now().UTC()
	huboErrores := err != nil || falloConsulta
	for _, endpoint := range informeJSON.Endpoints {
		if endpoint.Banner != nil && endpoint.Banner.Error != "" {
			huboErrores = true
		}
		if endpoint.Web != nil && endpoint.Web.Error != "" {
			huboErrores = true
		}
	}
	if errContexto := ctx.Err(); errContexto != nil {
		informeJSON.Estado = "cancelada"
		informeJSON.Error = errContexto.Error()
	} else if huboErrores {
		informeJSON.Estado = "con_errores"
		if err != nil {
			informeJSON.Error = err.Error()
		}
	}
	if *rutaReporte != "" {
		errGuardar := report.SaveJSON(*rutaReporte, informeJSON)
		if errGuardar != nil {
			fmt.Fprintf(os.Stderr, "Fallo al guardar, %q, %v\n", *rutaReporte, errGuardar)
			return 1
		}
		fmt.Printf("Guardado correctamente en %q\n", *rutaReporte)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al escanear: %v\n", err)
		return 1
	}
	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "Auditoría interrumpida: %v\n", ctx.Err())
		return 1
	}
	if huboErrores {
		return 1
	}
	return 0
}
