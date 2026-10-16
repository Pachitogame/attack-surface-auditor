package main

import (
	"attack-surface-auditor/internal/audit"
	"attack-surface-auditor/internal/vuln"
	"attack-surface-auditor/internal/webinspect"
	"fmt"
	"io"
	"net"
	"strconv"
)

func imprimirResultadoPuerto(destino io.Writer, resultado audit.ScanResult) {
	direccion := net.JoinHostPort(resultado.EndpointExaminado.DireccionObjetivo, strconv.Itoa(resultado.EndpointExaminado.Puerto))
	fmt.Fprintf(destino, "[TCP] %s | %s\n", direccion, resultado.Resultado.String())
	if resultado.DatosError != nil && resultado.Resultado != audit.EstadoCerrado {
		fmt.Fprintf(destino, "      Error: %q\n", resultado.DatosError.Error())
	}
}
func imprimirResultadoWeb(destino io.Writer, resultado webinspect.Result) {
	fmt.Fprintf(destino, "\n[WEB] %q\n", resultado.URL)
	if resultado.StatusCode != 0 {
		fmt.Fprintf(destino, "      Estado HTTP: %d\n", resultado.StatusCode)
	}
	if resultado.Title != "" {
		fmt.Fprintf(destino, "      Titulo: %q\n", resultado.Title)
	}
	if resultado.Error != nil {
		fmt.Fprintf(destino, "      Error: %q\n", resultado.Error.Error())
	}
}

func imprimirBanner(destino io.Writer, endpoint audit.Endpoint, datos []byte, err error) {
	direccion := net.JoinHostPort(endpoint.DireccionObjetivo, strconv.Itoa(endpoint.Puerto))
	fmt.Fprintf(destino, "\n[BANNER] %s\n", direccion)
	fmt.Fprintf(destino, "         Datos: %q\n", datos)
	if err != nil {
		fmt.Fprintf(destino, "         Error: %q\n", err.Error())
	}
}

func imprimirCVE(destino io.Writer, cve vuln.CVE) {
	fmt.Fprintf(destino, "\n[!] CVE candidato: %s\n", cve.ID)
	fmt.Fprintf(destino, "    Descripcion: %q\n", cve.Description)
	fmt.Fprintf(destino, "    Enlace: %s\n", cve.URL)
}
