package webinspect

import (
	"net/http"
	"time"
)

type Config struct {
	Timeout      time.Duration
	MaxBodyBytes int64
}

type Result struct {
	URL        string
	StatusCode int
	Headers    http.Header
	Title      string
	Error      error
}
