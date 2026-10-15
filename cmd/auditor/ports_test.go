package main

import "testing"

func TestParsePortsRangosYDuplicados(t *testing.T) {
	puertos, err := parsePorts("80, 80-82,81,443,443-443")
	if err != nil {
		t.Fatalf("Error, no se pudo completar el parseo, %v", err)
	}
	resultadoEsperado := []int{80, 81, 82, 443}
	if len(puertos) != len(resultadoEsperado) {
		t.Fatalf("Error, la longitud del resultado recibido y el esperado son diferentes, longitud esperada: %d, longitud recibida %d", resultadoEsperado, puertos)
	}
	for i, puerto := range resultadoEsperado {
		if puertos[i] != puerto {
			t.Fatalf("Error, los resultados obtenido y esperado son dispares, puerto esperado: %d, puerto recibido: %d", puerto, puertos[i])
		}
	}
}
func TestParsePortsRangoInvertido(t *testing.T) {
	puertos, err := parsePorts("90-80")
	if err == nil {
		t.Fatalf("t.Fatal(se esperaba un error por rango invertido, pero se recibió nil)")
	}
	if puertos != nil {
		t.Fatal("Se ha devuelto un slice de puertos, no debería haber pasado eso")
	}
}
