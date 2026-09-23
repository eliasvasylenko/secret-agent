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

// endpoint is one agent. address is unix:///path, http(s)://host, or
// ssh://[user@]host[:port][/socket] — the dial target, not an HTTP origin.
// URL path is remote dial-stdio -s only when sshd runs that requested command.
// Request URLs are always http(s); unix and ssh use http://unix/… (requestURL).
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
	case "http", "https", "ssh":
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
	if e.address != nil && e.address.Scheme == "ssh" {
		u := e.address
		transport.Proxy = nil
		transport.DisableKeepAlives = true
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialSSH(ctx, u)
		}
	}
	if e.tls != nil {
		transport.TLSClientConfig = e.tls.Clone()
	}
	// Attach is HTTP/1.1 only; advertise that in ALPN so HTTPS hops
	// (Caddy) do not negotiate h2 and then close.
	if e.address != nil && e.address.Scheme == "https" {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}
	return &http.Client{Transport: transport}
}

func (e endpoint) requestURL(apiPath string) *url.URL {
	base := &url.URL{Scheme: "http", Host: "unix"}
	if e.address != nil && (e.address.Scheme == "http" || e.address.Scheme == "https") {
		b := *e.address
		b.RawQuery = ""
		b.Fragment = ""
		base = &b
	}
	return base.JoinPath(strings.TrimPrefix(apiPath, "/"))
}

func unixEndpoint(socket string) endpoint {
	return endpoint{address: &url.URL{Scheme: "unix", Path: socket}}
}
