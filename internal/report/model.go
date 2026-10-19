package report

import (
	"attack-surface-auditor/internal/audit"
	"attack-surface-auditor/internal/fingerprint"
	"attack-surface-auditor/internal/vuln"
	"net/http"
	"time"
)

type EndpointReport struct {
	Endpoint     audit.Endpoint `json:"endpoint"`
	Estado       string         `json:"estado"`
	ErrorEscaneo string         `json:"error_escaneo,omitempty"`
	Banner       *BannerReport  `json:"banner,omitempty"`
	Web          *WebReport     `json:"web,omitempty"`
	Vuln         *VulnReport    `json:"vulnerabilidades,omitempty"`
}
type BannerReport struct {
	Datos    []byte                   `json:"datos_base64,omitempty"`
	Servicio *fingerprint.ServiceInfo `json:"servicio,omitempty"`
	Error    string                   `json:"error,omitempty"`
}
type WebReport struct {
	URL        string           `json:"url"`
	FinalURL   string           `json:"url_final,omitempty"`
	Redirects  []RedirectReport `json:"redirecciones,omitempty"`
	StatusCode int              `json:"codigo_estado"`
	Headers    http.Header      `json:"cabeceras,omitempty"`
	Title      string           `json:"titulo,omitempty"`
	Error      string           `json:"error,omitempty"`
}
type VulnReport struct {
	Query  vuln.Query `json:"consulta"`
	Estado string     `json:"estado"`
	CVEs   []vuln.CVE `json:"candidatos"`
	Error  string     `json:"error,omitempty"`
}
type Report struct {
	VersionFormato string           `json:"version_formato"`
	GeneradoEn     time.Time        `json:"generado_en"`
	Objetivo       string           `json:"objetivo"`
	Estado         string           `json:"estado"`
	Error          string           `json:"error,omitempty"`
	Endpoints      []EndpointReport `json:"endpoints"`
}
type RedirectReport struct {
	FromURL    string `json:"origen"`
	ToURL      string `json:"destino"`
	StatusCode int    `json:"codigo_estado"`
}
