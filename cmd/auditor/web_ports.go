package main

import "fmt"

func construirEsquemasWeb(httpTexto, httpsTexto string) (map[int]string, error) {
	puertosHTTP, err := parsePorts(httpTexto)
	if err != nil {
		return nil, fmt.Errorf("Error, lista de puertos HTTP inválida: %w", err)
	}
	puertosHTTPS, err := parsePorts(httpsTexto)
	if err != nil {
		return nil, fmt.Errorf("Error, lista de puertos HTTPS inválida: %w", err)
	}
	esquemas := make(map[int]string)
	for _, puerto := range puertosHTTP {
		esquemas[puerto] = "http"
	}
	for _, puerto := range puertosHTTPS {
		if _, existe := esquemas[puerto]; existe {
			return nil, fmt.Errorf("Error, el puerto %d aparece tanto en la lista HTTP como en la HTTPS", puerto)
		}
		esquemas[puerto] = "https"
	}
	return esquemas, nil
}
