package fingerprint

import (
	"attack-surface-auditor/internal/audit"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

func validarConfig(config Config) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("El timeout no puede ser menor o igual a 0, timeout recibido: %v", config.Timeout)
	}
	if config.MaxBytes < 1 || config.MaxBytes > 64*1024 {
		return fmt.Errorf("El numero máximo de bytes es inválido, ha de estar en el rango entre %d y %d, se ha introducido: %d", 1, 65536, config.MaxBytes)
	}
	return nil
}

func Grab(ctx context.Context, endpoint audit.Endpoint, config Config) BannerResult {
	resultado := BannerResult{
		Endpoint: endpoint,
		Datos:    nil,
		Error:    nil,
	}
	resultado.Error = validarConfig(config)
	if resultado.Error != nil {
		return resultado
	}
	err := ctx.Err()
	if err != nil {
		resultado.Error = err
		return resultado
	}
	resultado.Error = audit.ValidarEndpoint(endpoint)
	if resultado.Error != nil {
		return resultado
	}
	ctxGrab, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	direccion := net.JoinHostPort(endpoint.DireccionObjetivo, strconv.Itoa(endpoint.Puerto))
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctxGrab, "tcp", direccion)
	if err != nil {
		resultado.Error = err
		return resultado
	}
	defer conn.Close()
	deadline, ok := ctxGrab.Deadline()
	if ok {
		err = conn.SetReadDeadline(deadline)
		if err != nil {
			resultado.Error = err
			return resultado
		}
	}
	detenerCierre := context.AfterFunc(ctxGrab, func() { conn.Close() })
	defer detenerCierre()
	buferBytes := make([]byte, config.MaxBytes)
	total := 0
	for total < len(buferBytes) {
		n, err := conn.Read(buferBytes[total:])
		total += n
		if err != nil {
			errContexto := ctxGrab.Err()
			if errContexto != nil {
				resultado.Error = errContexto
			} else if !errors.Is(err, io.EOF) {
				resultado.Error = err
			}
			break
		}
		info, identificado := Identify(buferBytes[:total])
		if identificado && info.Servicio == "ssh" {
			break
		}
	}
	resultado.Datos = buferBytes[:total]
	return resultado
}
