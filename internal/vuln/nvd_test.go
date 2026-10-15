package vuln

import (
	"testing"
)

func TestValidarID(t *testing.T) {
	casos := []struct {
		id       string
		esperado bool
	}{
		{id: "CVE-2024-1234", esperado: true},
		{id: "CVE-2024-12345", esperado: true},
		{id: "CVE-24-1234", esperado: false},
		{id: "CVE-2024-123", esperado: false},
		{id: "CVE-2024-12x4", esperado: false},
		{id: "CVE-20x4-1234", esperado: false},
		{id: "CVE-2024-1234-extra", esperado: false},
		{id: "", esperado: false},
	}
	for _, caso := range casos {
		recibido := validarID(caso.id)
		if recibido != caso.esperado {
			t.Errorf("ID %q: esperado %t; recibido %t", caso.id, caso.esperado, recibido)
		}
	}
}

func TestValidarRespuesta(t *testing.T) {
	casos := []struct {
		nombre      string
		datos       respuestaNVD
		esperaError bool
	}{
		{nombre: "sin coincidencias", datos: respuestaNVD{
			ResultsPerPage: 0,
			StartIndex:     0,
			TotalResults:   0,
		},
			esperaError: false},
		{
			nombre: "pagina vacia con resultados pendientes", datos: respuestaNVD{
				ResultsPerPage: 2,
				StartIndex:     0,
				TotalResults:   3,
			},
			esperaError: true,
		},
		{nombre: "pagina valida", datos: respuestaNVD{
			ResultsPerPage:  2,
			StartIndex:      0,
			TotalResults:    3,
			Vulnerabilities: make([]vulnerabilidadNVD, 2),
		},
			esperaError: false},
		{
			nombre: "mas elementos que resultados restantes", datos: respuestaNVD{
				ResultsPerPage:  2,
				StartIndex:      2,
				TotalResults:    3,
				Vulnerabilities: make([]vulnerabilidadNVD, 2),
			},
			esperaError: true,
		},
	}
	for _, caso := range casos {
		err := validarRespuesta(caso.datos)
		if (err != nil) != caso.esperaError {
			t.Errorf("Error en el caso %q, se esperaba error %t, pero se ha recibido error %v", caso.nombre, caso.esperaError, err)
		}
	}
}
