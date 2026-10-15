package vuln

import (
	"fmt"
	"strings"
)

type descripcionNVD struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}
type cveNVD struct {
	ID           string           `json:"id"`
	Descriptions []descripcionNVD `json:"descriptions"`
}
type vulnerabilidadNVD struct {
	CVE cveNVD `json:"cve"`
}
type respuestaNVD struct {
	ResultsPerPage  int                 `json:"resultsPerPage"`
	StartIndex      int                 `json:"startIndex"`
	TotalResults    int                 `json:"totalResults"`
	Vulnerabilities []vulnerabilidadNVD `json:"vulnerabilities"`
}

func seleccionarDescripcion(descripciones []descripcionNVD) string {
	for _, descripcion := range descripciones {
		if descripcion.Lang == "en" && descripcion.Value != "" {
			return descripcion.Value
		}
	}
	return ""
}
func validarID(id string) bool {
	separacion := strings.Split(id, "-")
	if len(separacion) != 3 {
		return false
	}
	if separacion[0] != "CVE" {
		return false
	}
	if len(separacion[1]) != 4 {
		return false
	}
	if len(separacion[2]) < 4 {
		return false
	}
	for i := 1; i < 3; i++ {
		componente := separacion[i]
		for j := 0; j < len(componente); j++ {
			if componente[j] < '0' || componente[j] > '9' {
				return false
			}
		}
	}
	return true
}

func validarRespuesta(datos respuestaNVD) error {
	if datos.ResultsPerPage < 0 {
		return fmt.Errorf("Los resultados por pagina han de ser iguales o mayores a 0. Recibidos: %d", datos.ResultsPerPage)
	}
	if datos.StartIndex < 0 {
		return fmt.Errorf("El indice inicial ha de ser igual o mayor a 0. Recibido: %d", datos.StartIndex)
	}
	if datos.TotalResults < 0 {
		return fmt.Errorf("Los resultados totales han de ser iguales o mayores a 0. Recibidos: %d", datos.TotalResults)
	}
	if datos.StartIndex > datos.TotalResults {
		return fmt.Errorf("El indice inicial no puede ser mayor a los resultados totales. Indice: %d Resultados: %d", datos.StartIndex, datos.TotalResults)
	}
	if len(datos.Vulnerabilities) > datos.TotalResults-datos.StartIndex {
		return fmt.Errorf("Respuesta NVD incoherente: se recibieron %d vulnerabilidades, pero solo quedaban %d resultados", len(datos.Vulnerabilities), datos.TotalResults-datos.StartIndex)
	}
	if len(datos.Vulnerabilities) > datos.ResultsPerPage {
		return fmt.Errorf("Respuesta NVD incoherente: se recibieron %d vulnerabilidades, pero la página declara un máximo de %d", len(datos.Vulnerabilities), datos.ResultsPerPage)
	}
	if datos.StartIndex < datos.TotalResults && len(datos.Vulnerabilities) == 0 {
		return fmt.Errorf("Respuesta NVD incoherente: la página está vacía, pero quedan %d resultados desde el índice %d", datos.TotalResults-datos.StartIndex, datos.StartIndex)
	}
	return nil
}
