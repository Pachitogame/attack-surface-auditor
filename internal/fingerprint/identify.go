package fingerprint

import (
	"strings"
)

func Identify(datos []byte) (ServiceInfo, bool) {
	if len(datos) == 0 {
		return ServiceInfo{}, false
	}
	lineas := strings.Split(string(datos), "\n")
	for i, linea := range lineas {
		if i != len(lineas)-1 {
			longitudOriginal := len(linea) + 1
			linea = strings.TrimSuffix(linea, "\r")
			if !strings.HasPrefix(linea, "SSH-") {
				continue
			}
			if longitudOriginal > 255 || strings.ContainsRune(linea, '\x00') {
				return ServiceInfo{}, false
			}
			resto := strings.TrimPrefix(linea, "SSH-")
			partes := strings.SplitN(resto, "-", 2)
			if len(partes) != 2 {
				return ServiceInfo{}, false
			}
			version := partes[0]
			if version != "2.0" && version != "1.99" {
				return ServiceInfo{}, false
			}
			elementos := strings.SplitN(partes[1], " ", 2)
			software := elementos[0]
			if software == "" {
				return ServiceInfo{}, false
			}
			for j := 0; j < len(software); j++ {
				b := software[j]
				if b < 33 || b > 126 || b == '-' {
					return ServiceInfo{}, false
				}
			}
			return ServiceInfo{
				Servicio:         "ssh",
				VersionProtocolo: version,
				Software:         software,
			}, true
		}
	}
	return ServiceInfo{}, false
}
