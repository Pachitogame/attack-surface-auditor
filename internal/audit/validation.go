package audit

import (
	"fmt"
	"strings"
)

func ValidarEndpoint(endpoint Endpoint) error {
	if strings.TrimSpace(endpoint.DireccionObjetivo) == "" {
		return fmt.Errorf("dirección objetivo vacía")
	}
	if endpoint.Puerto < 1 || endpoint.Puerto > 65535 {
		return fmt.Errorf("Puerto inválido: %d, el intervalo válido es [1, 65535]", endpoint.Puerto)
	}
	return nil
}
