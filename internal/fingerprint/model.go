package fingerprint

import (
	"attack-surface-auditor/internal/audit"
	"time"
)

type Config struct {
	Timeout  time.Duration
	MaxBytes int
}
type BannerResult struct {
	Endpoint audit.Endpoint
	Datos    []byte
	Error    error
}
type ServiceInfo struct {
	Servicio         string
	VersionProtocolo string
	Software         string
}
