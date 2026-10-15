package main

import (
	"attack-surface-auditor/internal/audit"
	"attack-surface-auditor/internal/vuln"
	"context"
	"fmt"
	"sync"
)

type consultaVuln struct {
	Endpoint audit.Endpoint
	Query    vuln.Query
}
type resultadoVuln struct {
	Endpoint audit.Endpoint
	CVEs     []vuln.CVE
	Error    error
}

func workerVuln(ctx context.Context, cliente consultorVuln, config vuln.Config, jobs <-chan consultaVuln, results chan<- resultadoVuln) {
	for {
		select {
		case <-ctx.Done():
			return
		case consulta, ok := <-jobs:
			if !ok {
				return
			}
			cves, err := cliente.Lookup(ctx, consulta.Query, config)
			resultado := resultadoVuln{
				Endpoint: consulta.Endpoint,
				CVEs:     cves,
				Error:    err,
			}
			select {
			case results <- resultado:

			case <-ctx.Done():
				return
			}
		}
	}
}
func ejecutarConsultasVuln(ctx context.Context, cliente consultorVuln, config vuln.Config, consultas []consultaVuln, trabajadores int) ([]resultadoVuln, error) {
	if trabajadores < 1 || trabajadores > 256 {
		return nil, fmt.Errorf("Error, trabajadores se debe encontrar en el intervalo [1-256], se ha recibido %d", trabajadores)
	}
	if cliente == nil {
		return nil, fmt.Errorf("Error, el cliente recibido es nulo")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(consultas) == 0 {
		return []resultadoVuln{}, nil
	}
	jobs := make(chan consultaVuln)
	results := make(chan resultadoVuln)
	var wg sync.WaitGroup
	for i := 0; i < trabajadores; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			workerVuln(ctx, cliente, config, jobs, results)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(jobs)
		for _, consulta := range consultas {
			select {
			case jobs <- consulta:

			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	var resultados []resultadoVuln
	for resultado := range results {
		resultados = append(resultados, resultado)
	}
	if err := ctx.Err(); err != nil {
		return resultados, err
	}
	return resultados, nil
}

type consultorVuln interface {
	Lookup(context.Context, vuln.Query, vuln.Config) ([]vuln.CVE, error)
}
