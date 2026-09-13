package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// endpoint is one agent. address is unix:///path or http(s)://host — the
// dial target, not an HTTP origin. Request URLs are always http(s); unix
// sockets use http://unix/… (requestURL).
type endpoint struct {
	address *url.URL
	tls     *tls.Config
}

func parseEndpoint(address string) (endpoint, error) {
	u, err := url.Parse(address)
	if err != nil {
		return endpoint{}, fmt.Errorf("client address: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return endpoint{}, fmt.Errorf("client address: missing host")
		}
		return endpoint{address: u}, nil
	case "unix":
		if u.Host != "" {
			return endpoint{}, fmt.Errorf("client address: unix URL must not have a host")
		}
		path := u.Path
		if path == "" || path == "/" {
			return endpoint{}, fmt.Errorf("client address: missing unix socket path")
		}
		return unixEndpoint(path), nil
	case "":
		return unixEndpoint(address), nil
	default:
		return endpoint{}, fmt.Errorf("client address: unsupported scheme %q", u.Scheme)
	}
}

func unixEndpoint(socket string) endpoint {
	return endpoint{address: &url.URL{Scheme: "unix", Path: socket}}
}

func (e endpoint) requestURL(apiPath string) *url.URL {
	base := &url.URL{Scheme: "http", Host: "unix"}
	if e.address != nil && e.address.Scheme != "unix" {
		b := *e.address
		b.RawQuery = ""
		b.Fragment = ""
		base = &b
	}
	return base.JoinPath(strings.TrimPrefix(apiPath, "/"))
}

func (e endpoint) httpClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Attach is HTTP/1.1 101 Upgrade; HTTP/2 has no 101.
	p := new(http.Protocols)
	p.SetHTTP1(true)
	transport.Protocols = p
	if e.address != nil && e.address.Scheme == "unix" {
		socket := e.address.Path
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}
	}
	if e.tls != nil {
		transport.TLSClientConfig = e.tls.Clone()
	}
	return &http.Client{Transport: transport}
}
