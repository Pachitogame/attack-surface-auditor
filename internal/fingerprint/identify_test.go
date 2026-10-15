package fingerprint

import "testing"

func TestIdentifySSHConMensajePrevio(t *testing.T) {
	datos := []byte("Bienvenido\r\nSSH-2.0-OpenSSH_9.6 Ubuntu\r\n")
	info, ok := Identify(datos)
	if !ok {
		t.Fatalf("No se pudo identificar los datos aportados")
	}
	servicioEsperado := ServiceInfo{
		Servicio:         "ssh",
		VersionProtocolo: "2.0",
		Software:         "OpenSSH_9.6",
	}
	if servicioEsperado != info {
		t.Fatalf("El servicio obtenido es distinto al esperado. Obtenido: %+v, Esperado: %+v", info, servicioEsperado)
	}
}

func TestIdentifySSHIncompleto(t *testing.T) {
	datos := []byte("SSH-2.0-OpenSSH_9.6")
	info, ok := Identify(datos)
	if ok {
		t.Fatal("Se han podido identificar los datos aportados, no debería pasar eso")
	}
	esperado := ServiceInfo{}
	if info != esperado {
		t.Fatalf("El servicio obtenido es distinto al esperado. Obtenido: %+v, Esperado: %+v", info, esperado)
	}
}
