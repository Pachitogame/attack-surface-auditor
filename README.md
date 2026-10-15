# Attack Surface Auditor

Herramienta de línea de comandos desarrollada en Go para explorar puertos TCP, identificar servicios mediante sus banners, inspeccionar servicios web y consultar CVEs candidatos en NVD.

## Funcionalidades

- Escaneo de puertos TCP con concurrencia configurable.
- Captura de banners e identificación de servicios SSH.
- Inspección HTTP y HTTPS en los puertos 80 y 443.
- Extracción del título HTML y las cabeceras HTTP.
- Consulta de CVEs candidatos para versiones de OpenSSH identificadas.
- Exportación de resultados a JSON sin sobrescribir archivos existentes.
- Cancelación mediante Ctrl+C y conservación de los resultados obtenidos.

## Alcance y limitaciones

La identificación de servicios depende de la información anunciada en sus banners.

Las coincidencias de NVD son CVEs candidatos: requieren revisión para determinar si afectan al servicio analizado. La herramienta no verifica su explotación.

Utiliza esta herramienta únicamente sobre sistemas propios o para los que tengas autorización.
## Requisitos

- Go 1.26.4 o posterior.
- Acceso a Internet para consultar NVD con `-vuln`.

## Compilación

```powershell
git clone https://github.com/Pachitogame/attack-surface-auditor.git
cd attack-surface-auditor
go build -o auditor.exe ./cmd/auditor
```

## Ejemplos de uso

### Escanear puertos TCP

```powershell
.\auditor.exe -host 127.0.0.1 -ports "22,80,443,8000-8003"
```

### Capturar e identificar banners

```powershell
.\auditor.exe -host 127.0.0.1 -ports 22 -banner
```

### Inspeccionar servicios web

```powershell
.\auditor.exe -host 127.0.0.1 -ports "80,443" -web
```

### Consultar CVEs candidatos

La consulta requiere activar la captura de banners. Actualmente admite versiones compatibles de OpenSSH identificadas mediante un banner SSH.

```powershell
.\auditor.exe -host 127.0.0.1 -ports 22 -banner -vuln
```

### Guardar un informe JSON

```powershell
.\auditor.exe -host 127.0.0.1 -ports "22,80,443" -banner -web -output informe.json
```

El archivo de destino no debe existir. Si se interrumpe la ejecución con Ctrl+C, el informe conserva los resultados obtenidos hasta ese momento.

### Consultar las opciones disponibles

```powershell
.\auditor.exe -help
```
## Pruebas

```powershell
go vet ./...
go test -race ./... -count=1 -timeout=60s
```

El detector de carreras requiere CGO y un compilador C compatible. En Windows, puede utilizarse GCC de MSYS2 UCRT64.

Las pruebas utilizan servidores locales y clientes simulados; no necesitan consultar la API real de NVD.

GitHub Actions ejecuta el análisis, las pruebas con detector de carreras y la compilación en Linux y Windows.

## Estructura del proyecto

| Directorio | Responsabilidad |
| --- | --- |
| `cmd/auditor` | Interfaz de línea de comandos y coordinación de las consultas |
| `internal/audit` | Modelos y validaciones del escaneo |
| `internal/scanner` | Escaneo TCP concurrente |
| `internal/fingerprint` | Captura de banners e identificación de servicios |
| `internal/webinspect` | Inspección HTTP y HTTPS y extracción del título HTML |
| `internal/vuln` | Cliente de NVD, paginación y limitación de peticiones |
| `internal/report` | Modelos del informe y exportación a JSON |
## Informe de ejemplo

Puedes consultar un [informe JSON de una inspección web local](examples/informe-web.json).

Incluye el estado del puerto, la URL, el código de respuesta HTTP, las cabeceras y el título HTML.