package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func WriteJSON(destino io.Writer, informe Report) error {
	codificador := json.NewEncoder(destino)
	codificador.SetIndent("", "  ")
	err := codificador.Encode(informe)
	if err != nil {
		return fmt.Errorf("Error al codificar el informe. %w", err)
	}
	return nil
}

func SaveJSON(ruta string, informe Report) (err error) {
	if strings.TrimSpace(ruta) == "" {
		return fmt.Errorf("Error, no se aceptan rutas vacías")
	}
	archivo, err := os.OpenFile(ruta, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("Error a la hora de abrir el archivo en la ruta %q. %w", ruta, err)
	}
	guardado := false
	defer func() {
		errCierre := archivo.Close()
		if errCierre != nil && !errors.Is(errCierre, os.ErrClosed) {
			err = errors.Join(err, fmt.Errorf("Error al cerrar el archivo %q durante la limpieza: %w", ruta, errCierre))
		}

		if !guardado {
			errLimpieza := os.Remove(ruta)
			if errLimpieza != nil {
				err = errors.Join(err, fmt.Errorf("Error al eliminar el archivo incompleto %q: %w", ruta, errLimpieza))
			}
		}
	}()
	err = WriteJSON(archivo, informe)
	if err != nil {
		return fmt.Errorf("Error a la hora de escribir el archivo en la ruta %q. %w", ruta, err)
	}
	err = archivo.Close()
	if err != nil {
		return fmt.Errorf("Error, ha habido algun problema a la hora de cerrar el archivo. %w", err)
	}
	guardado = true
	return nil
}
