// Copyright 2023 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza-caddy/v2/modules/caddyhttp/reverseproxy"
	coreruleset "github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
	"github.com/jcchavezs/mergefs/io"
	"go.uber.org/zap"

	"github.com/spf13/cobra"
)

func init() {
	caddy.RegisterModule(corazaModule{})
	httpcaddyfile.RegisterHandlerDirective("coraza_waf", parseCaddyfile)
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "uucwaf",
		Usage: `[--directory <path>] [--from <addr>] [--to <addr>] [--change-host-header] [--insecure] [--internal-certs] [--disable-redirects] [--header-up "Field: value"] [--header-down "Field: value"] [--access-log] [--debug]`,
		Short: "Read rules from directory",
		Long: `
		EXPERIMENTAL: May be changed or removed.
		`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("rules", "R", "", "The input directory")
			cmd.Flags().StringP("from", "f", "localhost", "Address on which to receive traffic")
			cmd.Flags().StringSliceP("to", "t", []string{}, "Upstream address(es) to which traffic should be sent")
			cmd.Flags().BoolP("change-host-header", "c", false, "Set upstream Host header to address of upstream")
			cmd.Flags().BoolP("insecure", "", false, "Disable TLS verification (WARNING: DISABLES SECURITY BY NOT VERIFYING TLS CERTIFICATES!)")
			cmd.Flags().BoolP("disable-redirects", "r", false, "Disable HTTP->HTTPS redirects")
			cmd.Flags().BoolP("internal-certs", "i", false, "Use internal CA for issuing certs")
			cmd.Flags().StringSliceP("header-up", "H", []string{}, "Set a request header to send to the upstream (format: \"Field: value\")")
			cmd.Flags().StringSliceP("header-down", "d", []string{}, "Set a response header to send back to the client (format: \"Field: value\")")
			cmd.Flags().BoolP("access-log", "", false, "Enable the access log")
			cmd.Flags().BoolP("debug", "v", false, "Enable verbose debug logs")
			cmd.RunE = caddycmd.WrapCommandFuncForCobra(parseCommandLine)
		},
	})
}

// corazaModule is a Web Application Firewall implementation for Caddy.
type corazaModule struct {
	// deprecated
	Include      []string `json:"include"`
	Directives   string   `json:"directives"`
	LoadOWASPCRS bool     `json:"load_owasp_crs"`
	Whitelist    []string `json:"whitelist"`
    Blacklist    []string `json:"blacklist"`

	WList caddyhttp.MatchClientIP
	BList caddyhttp.MatchClientIP

	logger *zap.Logger
	waf    coraza.WAF
}

// CaddyModule returns the Caddy module information.
func (corazaModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return new(corazaModule) },
	}
}

// Provision implements caddy.Provisioner.
func (m *corazaModule) Provision(ctx caddy.Context) error {

	m.BList.Ranges = m.Blacklist
	m.BList.Provision(caddy.Context{})

	m.WList.Ranges = m.Whitelist
	m.WList.Provision(caddy.Context{})

	m.logger = ctx.Logger(m)

	config := coraza.NewWAFConfig().
		WithErrorCallback(newErrorCb(m.logger)).
		WithDebugLogger(newLogger(m.logger))
	if m.LoadOWASPCRS {
		config = config.WithRootFS(mergefs.Merge(coreruleset.FS, io.OSFS))
	}

	if m.Directives != "" {
		config = config.WithDirectives(m.Directives)
	}

	if len(m.Include) > 0 {
		m.logger.Warn("'include' field is deprecated, please use the Include directive inside 'directives' field instead")
		for _, file := range m.Include {
			if strings.Contains(file, "*") {
				m.logger.Debug("Preparing to expand glob", zap.String("pattern", file))
				// we get files as expandables globs (with wildcard patterns)
				fs, err := filepath.Glob(file)
				if err != nil {
					return err
				}
				m.logger.Debug("Glob expanded", zap.String("pattern", file), zap.Strings("files", fs))
				for _, f := range fs {
					config = config.WithDirectivesFromFile(f)
				}
			} else {
				m.logger.Debug("File was not a pattern, compiling it", zap.String("file", file))
				config = config.WithDirectivesFromFile(file)
			}
		}
	}

	var err error
	m.waf, err = coraza.NewWAF(config)
	return err
}

// Validate implements caddy.Validator.
func (m *corazaModule) Validate() error {
	return nil
}

var errInterruptionTriggered = errors.New("interruption triggered")

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m corazaModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

		if m.BList.Match(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return nil
		}

		if m.WList.Match(r) {
			return next.ServeHTTP(w, r)
		}

	id := randomString(16)
	tx := m.waf.NewTransactionWithID(id)
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	// Early return, Coraza is not going to process any rule
	if tx.IsRuleEngineOff() {
		// response writer is not going to be wrapped, but used as-is
		// to generate the response
		return next.ServeHTTP(w, r)
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.transaction_id", id)

	// ProcessRequest is just a wrapper around ProcessConnection, ProcessURI,
	// ProcessRequestHeaders and ProcessRequestBody.
	// It fails if any of these functions returns an error and it stops on interruption.
	if it, err := processRequest(tx, r); err != nil {
		return caddyhttp.HandlerError{
			StatusCode: http.StatusInternalServerError,
			ID:         tx.ID(),
			Err:        err,
		}
	} else if it != nil {
		return caddyhttp.HandlerError{
			StatusCode: obtainStatusCodeFromInterruptionOrDefault(it, http.StatusOK),
			ID:         tx.ID(),
			Err:        errInterruptionTriggered,
		}
	}

	ww, processResponse := wrap(w, r, tx)

	// We continue with the other middlewares by catching the response
	if err := next.ServeHTTP(ww, r); err != nil {
		return err
	}

	return processResponse(tx, r)
}

// Unmarshal Caddyfile implements caddyfile.Unmarshaler.
func (m *corazaModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Err("expected token following filter")
	}
	m.Include = []string{}
	for d.NextBlock(0) {
		key := d.Val()
		switch key {
		case "whitelist":
			var value string
			if !d.Args(&value) {
				// not enough args
				return d.ArgErr()
			}

			m.Whitelist = append(m.Whitelist, d.Val())

			for d.NextArg() {
				// too many args
				m.Whitelist = append(m.Whitelist, d.Val())
			}

		case "blacklist":
			var value string
			if !d.Args(&value) {
				// not enough args
				return d.ArgErr()
			}

			m.Blacklist = append(m.Blacklist, d.Val())

			for d.NextArg() {
				// too many args
				m.Blacklist = append(m.Blacklist, d.Val())
			}

		case "load_owasp_crs":
			if d.NextArg() {
				return d.ArgErr()
			}
			m.LoadOWASPCRS = true
		case "directives", "include":
			var value string
			if !d.Args(&value) {
				// not enough args
				return d.ArgErr()
			}

			if d.NextArg() {
				// too many args
				return d.ArgErr()
			}

			switch key {
			case "include":
				m.Include = append(m.Include, value)
			case "directives":
				m.Directives = value
			}
		default:
			return d.Errf("invalid key %q", key)
		}
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m corazaModule
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func newErrorCb(logger *zap.Logger) func(types.MatchedRule) {
	return func(mr types.MatchedRule) {
		logMsg := mr.ErrorLog()
		switch mr.Rule().Severity() {
		case types.RuleSeverityEmergency,
			types.RuleSeverityAlert,
			types.RuleSeverityCritical,
			types.RuleSeverityError:
			logger.Error(logMsg)
		case types.RuleSeverityWarning:
			logger.Warn(logMsg)
		case types.RuleSeverityNotice:
			logger.Info(logMsg)
		case types.RuleSeverityInfo:
			logger.Info(logMsg)
		case types.RuleSeverityDebug:
			logger.Debug(logMsg)
		}
	}
}

func parseCommandLine(fl caddycmd.Flags) (int, error) {
	var m corazaModule
	err := m.ParseCmdLine(fl)

	reverseproxy.CmdReverseProxy(fl, m)
	return caddy.ExitCodeSuccess, err
}

func (m *corazaModule) ParseCmdLine(fl caddycmd.Flags) error {
	fmt.Println("Parsing:",fl.String("rules"))
	flag := true
	m.LoadOWASPCRS = true
	if fl.String("rules") != "" {
		// to get directory
		dir := strings.TrimSpace(fl.String("rules"))
		// to read file names
		f, err := os.Open(dir)
		if err != nil {
			return err
		}
		files, err := f.Readdir(0)
		if err != nil {
			return err
		}
		for _, v := range files {
			if (v.Name() == "crs-setup.conf.example" || v.Name() == "coraza.conf-recommended") && !v.IsDir() {
				m.Directives = m.Directives + "Include " + dir + "/" + v.Name() + "\n"
			}else if v.Name() == "@owasp_crs" && v.IsDir() {
				m.Directives = m.Directives + "Include " + dir + "/" + v.Name() + "/*.conf" + "\n"
			}else if strings.Contains(v.Name(), ".conf") && flag {
				m.Directives = m.Directives + "Include " + dir + "/*.conf" + "\n"
				flag = false
			}
		}
		fmt.Println(m.Directives);
	}
	return nil
}
// Interface guards
var (
	_ caddy.Provisioner           = (*corazaModule)(nil)
	_ caddy.Validator             = (*corazaModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*corazaModule)(nil)
	_ caddyfile.Unmarshaler       = (*corazaModule)(nil)
)
