package scanner

import (
	"attack-surface-auditor/internal/audit"
	"context"
	"fmt"
	"sync"
)

func validarConfig(config audit.ScanConfig) error {
	if config.NMaxTrabajadores < 1 || config.NMaxTrabajadores > 256 {
		return fmt.Errorf("número de trabajadores inválido")
	}
	if config.TiempoLimite <= 0 {
		return fmt.Errorf("tiempo límite inválido")
	}
	return nil
}

func Scan(ctx context.Context, config audit.ScanConfig, endpoints []audit.Endpoint) ([]audit.ScanResult, error) {
	if err := validarConfig(config); err != nil {
		return nil, err
	}
	for _, endpoint := range endpoints {
		if err := audit.ValidarEndpoint(endpoint); err != nil {
			return nil, err
		}
	}
	err := ctx.Err()
	if err != nil {
		return nil, err
	}
	jobs := make(chan audit.Endpoint)
	resultados := make(chan audit.ScanResult)
	var wg sync.WaitGroup
	for i := 0; i < config.NMaxTrabajadores; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, jobs, resultados, config.TiempoLimite)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(jobs)
		for _, endpoint := range endpoints {
			select {
			case jobs <- endpoint:

			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(resultados)
	}()
	informe := []audit.ScanResult{}
	for resultado := range resultados {
		informe = append(informe, resultado)
	}
	err = ctx.Err()
	if err != nil {
		return informe, err
	}
	return informe, nil
}
