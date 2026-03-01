// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"time"
)

// Clients bundles the three clients + transports so you can close idle conns.
type Clients struct {
	API    *http.Client
	Probe  *http.Client
	Crawl  *http.Client
	apiTr  *http.Transport
	probTr *http.Transport
	crwlTr *http.Transport
}

// CloseIdleConnections is useful on session/engine shutdown.
// It does not kill in-flight requests, but it releases keep-alive sockets.
func (c *Clients) CloseIdleConnections() {
	if c.apiTr != nil {
		c.apiTr.CloseIdleConnections()
	}
	if c.probTr != nil {
		c.probTr.CloseIdleConnections()
	}
	if c.crwlTr != nil {
		c.crwlTr.CloseIdleConnections()
	}
}

// NewClients returns three tuned clients: API, Probe, Crawl.
func NewClients() (*Clients, error) {
	apiTr := newDefaultTransport()
	probTr := newProbeTransport(0)
	crwlTr, err := newCrawlTransport()
	if err != nil {
		return nil, err
	}

	return &Clients{
		API: &http.Client{Transport: apiTr, Timeout: 20 * time.Second},
		Probe: &http.Client{
			Transport: probTr,
			// for probes, prefer per-request context timeouts; keep a hard cap anyway
			Timeout: 8 * time.Second,
		},
		Crawl: &http.Client{
			Transport: crwlTr,
			// crawls can legitimately take longer. Use request contexts to bound if needed
			Timeout: 45 * time.Second,
		},
		apiTr:  apiTr,
		probTr: probTr,
		crwlTr: crwlTr,
	}, nil
}

func newDefaultTransport() *http.Transport {
	d := baseDialer(5*time.Second, 30*time.Second)

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,

		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   20,
		MaxConnsPerHost:       50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,

		// prefer correct TLS verification for APIs
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},

		DisableCompression: false, // allow gzip
	}
}

// ---- Probing client: short-lived, low reuse, high fan-out ----
//
// Intended for: HEAD/GET for status, banner grabs, lightweight fetches.
// Strategy: limit keep-alives so you don't retain lots of idle sockets,
// keep timeouts tight, and cap per-host concurrency.

func newProbeTransport(perHost int) *http.Transport {
	d := baseDialer(2*time.Second, 10*time.Second)

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,

		DialContext:       d.DialContext,
		ForceAttemptHTTP2: true,

		// keep this lower: probes spray across many hosts; idle pools become “memory”
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 2,
		MaxConnsPerHost:     10,
		IdleConnTimeout:     20 * time.Second,

		TLSHandshakeTimeout:   3 * time.Second,
		ExpectContinueTimeout: 0,
		ResponseHeaderTimeout: 4 * time.Second,

		// often you’ll hit junk certs during probing; keep verification on by default.
		// if you *must* allow insecure probing, fork a separate transport with InsecureSkipVerify=true
		// but be intentional about it
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},

		DisableCompression: true, // avoid spending CPU on gzip for tiny probe responses
	}
}

// ---- Crawling client: polite, reusable connections, cookies, longer reads ----
//
// Intended for: fetching pages/assets, following redirects (default policy),
// dealing with cookies, compression.
//
// Note: Cookie jar can grow; if you don’t need cookies, remove the jar.

func newCrawlTransport() (*http.Transport, error) {
	d := baseDialer(6*time.Second, 30*time.Second)

	// crawlers often benefit from cookies (sessions, pagination, etc.).
	// if you don't want cookies, you can omit the jar and still use the transport
	_, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,

		DialContext:       d.DialContext,
		ForceAttemptHTTP2: true,

		// crawling usually hits same hosts repeatedly; keep-alives pay off
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 32,
		MaxConnsPerHost:     32,
		IdleConnTimeout:     120 * time.Second,

		TLSHandshakeTimeout:   6 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 12 * time.Second,

		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},

		DisableCompression: false, // allow gzip to reduce bandwidth for HTML/JS/CSS
	}, nil
}

// baseDialer returns a dialer with sane defaults.
// keepAlive controls TCP keepalive probes at OS layer; it is NOT HTTP keep-alive.
func baseDialer(timeout, keepAlive time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: keepAlive,
	}
}
