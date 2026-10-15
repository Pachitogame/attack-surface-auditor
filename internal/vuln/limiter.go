package vuln

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/time/rate"
)

type Limitador interface {
	Wait(context.Context) error
}

func NewLimiter(intervalo time.Duration) (Limitador, error) {
	if intervalo <= 0 {
		return nil, fmt.Errorf("No se aceptan intervalos iguales o menores a 0, se recibió %v", intervalo)
	}
	ratio := rate.Every(intervalo)
	limitador := rate.NewLimiter(ratio, 1)
	return limitador, nil
}
