package audit

import (
	"time"
)

type Endpoint struct {
	DireccionObjetivo string
	Puerto            int
}

type ScanConfig struct {
	NMaxTrabajadores int
	TiempoLimite     time.Duration
}

type ScanResult struct {
	EndpointExaminado Endpoint
	Resultado         EstadoPuerto
	DatosError        error
}
type EstadoPuerto int

const (
	EstadoIndeterminado EstadoPuerto = iota
	EstadoAbierto
	EstadoCerrado
	EstadoTimeout
	EstadoCancelado
)

func (e EstadoPuerto) String() string {
	switch e {
	case EstadoIndeterminado:
		return "Indeterminado"
	case EstadoAbierto:
		return "Abierto"
	case EstadoCerrado:
		return "Cerrado"
	case EstadoTimeout:
		return "Timeout"
	case EstadoCancelado:
		return "Cancelado"
	default:
		return "Desconocido"
	}
}
