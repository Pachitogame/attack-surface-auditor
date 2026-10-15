package webinspect

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"golang.org/x/net/html"
)

func extraerTitulo(cuerpo []byte) (string, error) {
	lector := bytes.NewReader(cuerpo)
	tokenizador := html.NewTokenizer(lector)
	dentroTitulo := false
	var titulo strings.Builder
	for {
		tipo := tokenizador.Next()
		switch tipo {
		case html.ErrorToken:
			err := tokenizador.Err()
			if errors.Is(err, io.EOF) {
				return titulo.String(), nil
			}
			return "", err
		case html.StartTagToken:
			token := tokenizador.Token()
			if token.Data == "title" {
				dentroTitulo = true
			}
		case html.TextToken:
			if dentroTitulo {
				token := tokenizador.Token()
				titulo.WriteString(token.Data)
			}
		case html.EndTagToken:
			token := tokenizador.Token()
			if dentroTitulo && token.Data == "title" {
				return titulo.String(), nil
			}
		}
	}
}
