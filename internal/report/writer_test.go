package report

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveJSONConservaArchivo(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "informe.json")
	reporte := Report{
		VersionFormato: "1.0",
		Objetivo:       "127.0.0.1",
		Estado:         "completada",
		Endpoints:      []EndpointReport{},
	}
	err := SaveJSON(ruta, reporte)
	if err != nil {
		t.Fatalf("Error al guardar el archivo %v", err)
	}
	bytes, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("Error al leer el archivo %v", err)
	}
	var recuperado Report
	err = json.Unmarshal(bytes, &recuperado)
	if err != nil {
		t.Fatalf("Error al deserializar los bytes del reporte %v", err)
	}
	if recuperado.Objetivo != reporte.Objetivo {
		t.Errorf("Error, se esperaba recibir el objetivo %q, sin embargo se recibió %q", reporte.Objetivo, recuperado.Objetivo)
	}
	if recuperado.VersionFormato != reporte.VersionFormato {
		t.Errorf("Error, se esperaba recibir la version %q, sin embargo se recibió la version %q", reporte.VersionFormato, recuperado.VersionFormato)
	}
}

func TestSaveJSONNoSobreescribe(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "existente.json")
	err := os.WriteFile(ruta, []byte("contenido original"), 0600)
	if err != nil {
		t.Fatalf("Error al escribir en el archivo, %v", err)
	}
	var reporte Report
	err = SaveJSON(ruta, reporte)
	if err == nil {
		t.Fatal("Error, se esperaba recibir un error pero no se recibió nada")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("Error, se recibió un error que no se esperaba, %v", err)
	}
	contenido, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("Error al leer el archivo, %v", err)
	}
	if string(contenido) != "contenido original" {
		t.Fatalf("Error, se esperaba que el contenido continuase siendo `contenido original`, sin embargo se recibió %q", string(contenido))
	}
}

func TestSaveJSONEliminarArchivoFallido(t *testing.T) {
	reporte := Report{
		GeneradoEn: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
	ruta := filepath.Join(t.TempDir(), "informe.json")
	err := SaveJSON(ruta, reporte)
	if err == nil {
		t.Fatalf("Error, se esperaba que se devolviese un error, sin embargo no se recibió nada")
	}
	var errSerializacion *json.MarshalerError
	if !errors.As(err, &errSerializacion) {
		t.Fatalf("Error, se esperaba un error de serializacion JSON, sin embargo se ha recibido %v", err)
	}
	_, errStat := os.Stat(ruta)
	if !errors.Is(errStat, os.ErrNotExist) {
		t.Fatalf("Error, se recibió un error distinto al esperado, %v", errStat)
	}
}
