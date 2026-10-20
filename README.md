# Attack Surface Auditor
[![Go CI](https://github.com/Pachitogame/attack-surface-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Pachitogame/attack-surface-auditor/actions/workflows/ci.yml)
Herramienta de línea de comandos desarrollada en Go para explorar puertos TCP, identificar servicios mediante sus banners, inspeccionar servicios web y consultar CVEs candidatos en NVD.

## Funcionalidades

- Escaneo de puertos TCP con concurrencia configurable.
- Resultados durante el escaneo y progreso periódico.
- Filtro de consola para mostrar únicamente los puertos abiertos.
- Seguimiento limitado de redirecciones web.
- Captura de banners e identificación de servicios SSH.
- Inspección HTTP y HTTPS en puertos configurables.
- Extracción del título HTML y las cabeceras HTTP.
- Consulta de CVEs candidatos para versiones de OpenSSH identificadas.
- Exportación de resultados a JSON sin sobrescribir archivos existentes.
- Cancelación mediante Ctrl+C y conservación de los resultados obtenidos.

## Alcance y limitaciones

La identificación de servicios depende de la información anunciada en sus banners.

Las coincidencias de NVD son CVEs candidatos: requieren revisión para determinar si afectan al servicio analizado. La herramienta no verifica su explotación.

Utiliza esta herramienta únicamente sobre sistemas propios o para los que tengas autorización.
## Requisitos

- Para utilizar los ejecutables descargables no necesitas instalar Go.
- Para compilar el código necesitas Go 1.26.4 o posterior.
- La consulta de CVEs con `-vuln` requiere acceso a Internet.
- Los ejemplos utilizan servicios locales; si no están escuchando, los puertos aparecerán cerrados.

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

### Mostrar únicamente puertos abiertos

```powershell
.\auditor.exe -host 127.0.0.1 -ports "1-65535" -workers 100 -open -output escaneo-completo.json
```

Los resultados aparecen conforme termina cada conexión y el progreso se actualiza aproximadamente cada segundo.

`-open` filtra únicamente la consola. El informe JSON conserva todos los resultados recogidos, incluidos los puertos cerrados.

El escaneo utiliza conexiones TCP; no incluye UDP. Puedes interrumpirlo con Ctrl+C.

El progreso y el filtro `-open` se incluirán en v0.2.0; no están disponibles en los ejecutables de v0.1.0.

### Capturar e identificar banners

```powershell
.\auditor.exe -host 127.0.0.1 -ports 22 -banner
```

La captura termina al recibir una identificación SSH completa y válida, sin esperar a que el servidor cierre la conexión.

Para otros servicios, la captura es pasiva: espera datos hasta el cierre de la conexión, el límite de bytes o el timeout. Los servicios que requieren una petición del cliente pueden no enviar un banner espontáneamente.

La finalización anticipada de la captura SSH se incluirá en v0.2.0; el ejecutable publicado de v0.1.0 todavía no la incluye.

### Inspeccionar servicios web

```powershell
.\auditor.exe -host 127.0.0.1 -ports "80,443" -web
```

### Redirecciones web

La inspección web sigue hasta 5 redirecciones por defecto. Puedes configurar el límite entre 0 y 10:

```powershell
.\auditor.exe -host 127.0.0.1 -ports 80 -web -web-max-redirects 3
```

Para desactivar el seguimiento:

```powershell
.\auditor.exe -host 127.0.0.1 -ports 80 -web -web-max-redirects 0
```

Solo se permiten redirecciones al mismo nombre de host. Se permite cambiar de puerto y pasar de HTTP a HTTPS, pero se bloquean los cambios a otro host y de HTTPS a HTTP.

El tiempo configurado con `-web-timeout` se aplica a toda la inspección, incluidas las redirecciones y la lectura del cuerpo.

La consola y el informe JSON incluyen la URL final y los saltos autorizados. Un salto registrado puede terminar en un error de conexión; no implica que su destino haya respondido correctamente.

Esta funcionalidad está disponible en el código de desarrollo y se incluirá en v0.2.0. Los ejecutables publicados de v0.1.0 todavía no la incluyen.

### Consultar CVEs candidatos

La consulta requiere activar la captura de banners. Actualmente admite versiones compatibles de OpenSSH identificadas mediante un banner SSH.

```powershell
.\auditor.exe -host 127.0.0.1 -ports 22 -banner -vuln
```

### Inspeccionar servicios web en puertos personalizados

```powershell
.\auditor.exe -host 127.0.0.1 -ports "8000,8443" -web -web-http-ports "80,8000" -web-https-ports "443,8443"
```

`-ports` determina qué puertos se escanean. Las listas `-web-http-ports` y `-web-https-ports` indican qué protocolo utilizar para inspeccionar los puertos abiertos; no añaden puertos al escaneo.

Ambas listas admiten puertos separados por comas y rangos inclusivos. No pueden estar vacías ni compartir un mismo puerto.

Por defecto se utiliza HTTP para el puerto 80 y HTTPS para el 443. La inspección HTTPS mantiene la validación de certificados.

Esta funcionalidad se incluirá en v0.2.0; los ejecutables publicados de v0.1.0 todavía no la incluyen.

### Guardar un informe JSON

```powershell
.\auditor.exe -host 127.0.0.1 -ports "22,80,443" -banner -web -output informe.json
```

El archivo de destino no debe existir. Si se interrumpe la ejecución con Ctrl+C, el informe conserva los resultados obtenidos hasta ese momento.

### Consultar las opciones disponibles

Si descargaste el ejecutable para Windows desde Releases:

```powershell
.\auditor-windows-amd64.exe -help
```

Si lo compilaste siguiendo las instrucciones anteriores:

```powershell
.\auditor.exe -help
```

### Uso en Linux

Después de descargar el ejecutable para Linux x64 desde Releases:

```bash
chmod +x auditor-linux-amd64
./auditor-linux-amd64 -help
./auditor-linux-amd64 -host 127.0.0.1 -ports "22,80,443"
```

Para compilar desde el código fuente en Linux:

```bash
go build -o auditor ./cmd/auditor
./auditor -help
```

Los parámetros son los mismos que en Windows; cambia el nombre y la forma de invocar el ejecutable.

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

## Descargas

Los ejecutables para Windows x64 y Linux x64 están disponibles en la [versión v0.1.0](https://github.com/Pachitogame/attack-surface-auditor/releases/tag/v0.1.0).
## Uso de IA durante el desarrollo

El código de la herramienta ha sido construido por mí como parte de mi aprendizaje de Go, redes y ciberseguridad.

He utilizado ChatGPT como apoyo para crear pruebas, obtener información sobre bibliotecas, depurar errores y preparar la documentación y la presentación del repositorio en GitHub.

Durante el proceso también he recibido orientación sobre arquitectura y ejemplos de código, que he revisado e integrado. La implementación y las comprobaciones de funcionamiento las he realizado yo.