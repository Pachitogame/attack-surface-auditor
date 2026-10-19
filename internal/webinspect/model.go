package webinspect

import (
	"net/http"
	"time"
)

type Config struct {
	Timeout      time.Duration
	MaxBodyBytes int64
	MaxRedirects int
}

type Result struct {
	URL        string
	FinalURL   string
	Redirects  []Redirect
	StatusCode int
	Headers    http.Header
	Title      string
	Error      error
}
type Redirect struct {
	FromURL    string
	ToURL      string
	StatusCode int
}
