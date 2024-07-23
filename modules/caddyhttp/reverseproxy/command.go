// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reverseproxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func CmdReverseProxy(fs caddycmd.Flags,m caddyhttp.MiddlewareHandler) (int, error) {
	caddy.TrapSignals()

	// fmt.Println(m)
	from := fs.String("from")
	changeHost := fs.Bool("change-host-header")
	insecure := fs.Bool("insecure")
	disableRedir := fs.Bool("disable-redirects")
	internalCerts := fs.Bool("internal-certs")
	accessLog := fs.Bool("access-log")
	debug := fs.Bool("debug")

	httpPort := strconv.Itoa(caddyhttp.DefaultHTTPPort)
	httpsPort := strconv.Itoa(caddyhttp.DefaultHTTPSPort)

	to, err := fs.GetStringSlice("to")
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid to flag: %v", err)
	}
	if len(to) == 0 {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("--to is required")
	}

	// set up the downstream address; assume missing information from given parts
	fromAddr, err := httpcaddyfile.ParseAddress(from)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid downstream address %s: %v", from, err)
	}
	if fromAddr.Path != "" {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("paths are not allowed: %s", from)
	}
	if fromAddr.Scheme == "" {
		if fromAddr.Port == httpPort || fromAddr.Host == "" {
			fromAddr.Scheme = "http"
		} else {
			fromAddr.Scheme = "https"
		}
	}
	if fromAddr.Port == "" {
		if fromAddr.Scheme == "http" {
			fromAddr.Port = httpPort
		} else if fromAddr.Scheme == "https" {
			fromAddr.Port = httpsPort
		}
	}

	// set up the upstream address; assume missing information from given parts
	// mixing schemes isn't supported, so use first defined (if available)
	toAddresses := make([]string, len(to))
	var toScheme string
	for i, toLoc := range to {
		addr, err := parseUpstreamDialAddress(toLoc)
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid upstream address %s: %v", toLoc, err)
		}
		if addr.scheme != "" && toScheme == "" {
			toScheme = addr.scheme
		}
		toAddresses[i] = addr.dialAddr()
	}

	// proceed to build the handler and server
	ht := reverseproxy.HTTPTransport{}
	if toScheme == "https" {
		ht.TLS = new(reverseproxy.TLSConfig)
		if insecure {
			ht.TLS.InsecureSkipVerify = true
		}
	}

	upstreamPool := reverseproxy.UpstreamPool{}
	for _, toAddr := range toAddresses {
		parsedAddr, err := caddy.ParseNetworkAddress(toAddr)
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid upstream address %s: %v", toAddr, err)
		}

		if parsedAddr.StartPort == 0 && parsedAddr.EndPort == 0 {
			// unix networks don't have ports
			upstreamPool = append(upstreamPool, &reverseproxy.Upstream{
				Dial: toAddr,
			})
		} else {
			// expand a port range into multiple upstreams
			for i := parsedAddr.StartPort; i <= parsedAddr.EndPort; i++ {
				upstreamPool = append(upstreamPool, &reverseproxy.Upstream{
					Dial: caddy.JoinNetworkAddress("", parsedAddr.Host, fmt.Sprint(i)),
				})
			}
		}
	}

	handler := reverseproxy.Handler{
		TransportRaw: caddyconfig.JSONModuleObject(ht, "protocol", "http", nil),
		Upstreams:    upstreamPool,
	}

	// set up header_up
	headerUp, err := fs.GetStringSlice("header-up")
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid header flag: %v", err)
	}
	if len(headerUp) > 0 {
		reqHdr := make(http.Header)
		for i, h := range headerUp {
			key, val, found := strings.Cut(h, ":")
			key, val = strings.TrimSpace(key), strings.TrimSpace(val)
			if !found || key == "" || val == "" {
				return caddy.ExitCodeFailedStartup, fmt.Errorf("header-up %d: invalid format \"%s\" (expecting \"Field: value\")", i, h)
			}
			reqHdr.Set(key, val)
		}
		handler.Headers = &headers.Handler{
			Request: &headers.HeaderOps{
				Set: reqHdr,
			},
		}
	}

	// set up header_down
	headerDown, err := fs.GetStringSlice("header-down")
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid header flag: %v", err)
	}
	if len(headerDown) > 0 {
		respHdr := make(http.Header)
		for i, h := range headerDown {
			key, val, found := strings.Cut(h, ":")
			key, val = strings.TrimSpace(key), strings.TrimSpace(val)
			if !found || key == "" || val == "" {
				return caddy.ExitCodeFailedStartup, fmt.Errorf("header-down %d: invalid format \"%s\" (expecting \"Field: value\")", i, h)
			}
			respHdr.Set(key, val)
		}
		if handler.Headers == nil {
			handler.Headers = &headers.Handler{}
		}
		handler.Headers.Response = &headers.RespHeaderOps{
			HeaderOps: &headers.HeaderOps{
				Set: respHdr,
			},
		}
	}

	if changeHost {
		if handler.Headers == nil {
			handler.Headers = &headers.Handler{
				Request: &headers.HeaderOps{
					Set: http.Header{},
				},
			}
		}
		handler.Headers.Request.Set.Set("Host", "{http.reverse_proxy.upstream.hostport}")
	}

	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(m, "handler", "waf", nil),
			caddyconfig.JSONModuleObject(handler, "handler", "reverse_proxy", nil),
		},
	}

	
	if fromAddr.Host != "" {
		route.MatcherSetsRaw = []caddy.ModuleMap{
			{
				"host": caddyconfig.JSON(caddyhttp.MatchHost{fromAddr.Host}, nil),
			},
		}
	}

	server := &caddyhttp.Server{
		Routes: caddyhttp.RouteList{route},
		Listen: []string{":" + fromAddr.Port},
	}
	if accessLog {
		server.Logs = &caddyhttp.ServerLogConfig{}
	}

	if fromAddr.Scheme == "http" {
		server.AutoHTTPS = &caddyhttp.AutoHTTPSConfig{Disabled: true}
	} else if disableRedir {
		server.AutoHTTPS = &caddyhttp.AutoHTTPSConfig{DisableRedir: true}
	}

	httpApp := caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{"proxy": server},
	}

	appsRaw := caddy.ModuleMap{
		"http": caddyconfig.JSON(httpApp, nil),
	}
	if internalCerts && fromAddr.Host != "" {
		tlsApp := caddytls.TLS{
			Automation: &caddytls.AutomationConfig{
				Policies: []*caddytls.AutomationPolicy{{
					SubjectsRaw: []string{fromAddr.Host},
					IssuersRaw:  []json.RawMessage{json.RawMessage(`{"module":"internal"}`)},
				}},
			},
		}
		appsRaw["tls"] = caddyconfig.JSON(tlsApp, nil)
	}

	var false bool
	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{
			Disabled: true,
			Config: &caddy.ConfigSettings{
				Persist: &false,
			},
		},
		AppsRaw: appsRaw,
	}

	if debug {
		cfg.Logging = &caddy.Logging{
			Logs: map[string]*caddy.CustomLog{
				"default": {BaseLog: caddy.BaseLog{Level: zap.DebugLevel.CapitalString()}},
			},
		}
	}

	err = caddy.Run(cfg)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	caddy.Log().Info("caddy proxying", zap.String("from", fromAddr.String()), zap.Strings("to", toAddresses))
	if len(toAddresses) > 1 {
		caddy.Log().Info("using default load balancing policy", zap.String("policy", "random"))
	}

	select {}
}
