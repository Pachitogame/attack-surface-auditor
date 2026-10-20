package main

import "testing"

func TestConstruirEsquemasWeb(t *testing.T) {
	esquemas, err := construirEsquemasWeb("80,8000-8001,80", "443,8443")
	if err != nil {
		t.Fatalf("Error, no se esperba ningun error, %v", err)
	}
	esperados := map[int]string{
		80:   "http",
		8000: "http",
		8001: "http",
		443:  "https",
		8443: "https",
	}

	if len(esquemas) != len(esperados) {
		t.Fatalf("Error, se esperaba recibir %d, puertos, sin embargo se recibieron %d", len(esperados), len(esquemas))
	}
	for puerto, esperado := range esperados {
		if esquemas[puerto] != esperado {
			t.Errorf("Error del puerto %d, esquema esperado: %q, recibido: %q", puerto, esperado, esquemas[puerto])
		}
	}
}

func TestConstruirEsquemasWebRechazaConflicto(t *testing.T) {
	esquemas, err := construirEsquemasWeb("80,8000", "443,8000")
	if err == nil {
		t.Fatal("Error, se esperaba recibir un error ya que se ha asignado el puerto 8000 a ambos protocolos")
	}
	if esquemas != nil {
		t.Fatalf("Error, no se esperaba recibir un mapa parcial, se recibió: %v", esquemas)
	}
}
