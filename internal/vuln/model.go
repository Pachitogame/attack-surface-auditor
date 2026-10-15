package vuln

import (
	"net/http"
	"time"
)

type Query struct {
	Vendor  string
	Product string
	Version string
}
type CVE struct {
	ID          string
	Description string
	URL         string
}
type Config struct {
	Timeout      time.Duration
	MaxBodyBytes int64
}

type Client struct {
	httpClient *http.Client
	limitador  Limitador
}
