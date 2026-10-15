package vuln

import (
	"attack-surface-auditor/internal/fingerprint"
	"strings"
)

func QueryFromService(info fingerprint.ServiceInfo) (Query, bool) {
	if info.Servicio != "ssh" {
		return Query{}, false
	}
	if info.Software == "" {
		return Query{}, false
	}
	if !strings.HasPrefix(info.Software, "OpenSSH_") {
		return Query{}, false
	}
	version := strings.TrimPrefix(info.Software, "OpenSSH_")
	if version == "" {
		return Query{}, false
	}
	if !validarVersionOpenSSH(version) {
		return Query{}, false
	}
	return Query{
		Vendor:  "openbsd",
		Product: "openssh",
		Version: version,
	}, true
}

func validarVersionOpenSSH(version string) bool {
	partesVersion := strings.Split(version, "p")
	if len(partesVersion) > 2 {
		return false
	}
	if len(partesVersion) == 2 {
		if partesVersion[1] == "" {
			return false
		}
	}
	numeros := strings.Split(partesVersion[0], ".")
	if len(numeros) != 2 || numeros[0] == "" || numeros[1] == "" {
		return false
	}
	if len(partesVersion) == 2 {
		numeros = append(numeros, partesVersion[1])
	}
	for i := 0; i < len(numeros); i++ {
		componente := numeros[i]
		for j := 0; j < len(componente); j++ {
			b := componente[j]
			if b < '0' || b > '9' {
				return false
			}
		}
	}
	return true
}
