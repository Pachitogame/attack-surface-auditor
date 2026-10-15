package main

import (
	"fmt"
	"strconv"
	"strings"
)

func parsePorts(puertos string) ([]int, error) {
	if strings.TrimSpace(puertos) == "" {
		return nil, fmt.Errorf("La lista de puertos esta vacia")
	}
	partes := strings.Split(puertos, ",")
	lista := []int{}
	vistos := make(map[int]bool)
	for i, parte := range partes {
		parteAjustada := strings.TrimSpace(parte)
		if parteAjustada == "" {
			return nil, fmt.Errorf("Puerto vacio en la lista de puertos, posicion: %d", i+1)
		}
		if strings.Contains(parteAjustada, "-") {
			inicio, fin, err := parsePortRange(parteAjustada)
			if err != nil {
				return nil, fmt.Errorf("Puerto invalido en la lista de puertos, posicion: %d, error: %w, parte: %q", i+1, err, parteAjustada)
			}
			for i := inicio; i <= fin; i++ {
				if !vistos[i] {
					vistos[i] = true
					lista = append(lista, i)
				}
			}
			continue
		}
		puerto, err := parsePortNumber(parteAjustada)
		if err != nil {
			return nil, fmt.Errorf("Puerto invalido en la lista de puertos, posicion: %d, error: %w, parte: %q", i+1, err, parteAjustada)
		}
		if vistos[puerto] {
			continue
		}
		vistos[puerto] = true
		lista = append(lista, puerto)
	}
	return lista, nil
}
func parsePortNumber(texto string) (int, error) {
	texto = strings.TrimSpace(texto)
	puerto, err := strconv.Atoi(texto)
	if err != nil {
		return 0, fmt.Errorf("Puerto invalido: %q, error: %w", texto, err)
	}
	if puerto < 1 || puerto > 65535 {
		return 0, fmt.Errorf("Puerto fuera de rango: %d, intervalo permitido: 1-65535", puerto)
	}
	return puerto, nil
}
func parsePortRange(texto string) (int, int, error) {
	textoSeparado := strings.Split(texto, "-")
	if len(textoSeparado) != 2 {
		return 0, 0, fmt.Errorf("Rango de puertos inválido: %q; formato esperado: inicio-fin", texto)
	}
	inicio, err := parsePortNumber(textoSeparado[0])
	if err != nil {
		return 0, 0, fmt.Errorf("Puerto inicial inválido: %w", err)
	}
	fin, err := parsePortNumber(textoSeparado[1])
	if err != nil {
		return 0, 0, fmt.Errorf("Puerto final inválido: %w", err)
	}
	if inicio > fin {
		return 0, 0, fmt.Errorf("Rango de puertos inválido: el inicio %d supera al fin %d", inicio, fin)
	}
	return inicio, fin, nil

}
