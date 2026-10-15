package webinspect

import "testing"

func TestExtraerTitulo(t *testing.T) {
	cuerpo := []byte("<html><head><TITLE>Auditor &amp; Servicios</TITLE></head><body>Otro texto</body></html>")
	titulo, err := extraerTitulo(cuerpo)
	if err != nil {
		t.Fatalf("No se pudo extraer el titulo del cuerpo. %v", err)
	}
	if titulo != "Auditor & Servicios" {
		t.Fatalf("título recibido: %q; esperado: %q", titulo, "Auditor & Servicios")
	}

}
