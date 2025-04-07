package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/alexferl/huma-echo-boilerplate/logger"
	"github.com/alexferl/huma-echo-boilerplate/service"
)

// Config holds all global configuration for our program.
type Config struct {
	AppName      string
	EnvName      string
	ConfigPrefix string
	ConfigType   string
	ConfigPaths  []string
	Logger       *logger.Config
	Service      service.Config
}

// New creates a Config instance.
func New() *Config {
	return &Config{
		AppName:      "app",
		EnvName:      "local",
		ConfigPrefix: "config",
		ConfigType:   "toml",
		ConfigPaths:  []string{"./configs", "/configs"},
		Logger:       logger.DefaultConfig,
		Service:      service.DefaultConfig,
	}
}

const (
	AppName      = "app-name"
	EnvName      = "env-name"
	ConfigPrefix = "config-prefix"
	ConfigType   = "config-type"
	ConfigPaths  = "config-paths"

	BodyLimitLimit = "body-limit"

	CompressEnabled   = "compress-enabled"
	CompressLevel     = "compress-level"
	CompressMinLength = "compress-min-length"

	CORSEnabled          = "cors-enabled"
	CORSAllowOrigins     = "cors-allow-origins"
	CORSAllowMethods     = "cors-allow-methods"
	CORSAllowHeaders     = "cors-allow-headers"
	CORSAllowCredentials = "cors-allow-credentials"
	CORSExposeHeaders    = "cors-expose-headers"
	CORSMaxAge           = "cors-max-age"

	CSRFEnabled        = "csrf-enabled"
	CSRFTokenLength    = "csrf-token-length"
	CSRFTokenLookup    = "csrf-token-lookup"
	CSRFContextKey     = "csrf-context-key"
	CSRFCookieName     = "csrf-cookie-name"
	CSRFCookieDomain   = "csrf-cookie-domain"
	CSRFCookiePath     = "csrf-cookie-path"
	CSRFCookieMaxAge   = "csrf-cookie-max-age"
	CSRFCookieSecure   = "csrf-cookie-secure"
	CSRFCookieHTTPOnly = "csrf-cookie-http-only"
	CSRFCookieSameSite = "csrf-cookie-same-site"

	HealthcheckEnabled           = "healthcheck-enabled"
	HealthcheckLivenessEndpoint  = "healthcheck-liveness-endpoint"
	HealthcheckReadinessEndpoint = "healthcheck-readiness-endpoint"
	HealthcheckStartupEndpoint   = "healthcheck-startup-endpoint"

	HTTPBindAddr          = "http-bind-addr"
	HTTPLogRequests       = "http-log-requests"
	HTTPGracefulTimeout   = "http-graceful-timeout"
	HTTPIdleTimeout       = "http-idle-timeout"
	HTTPReadTimeout       = "http-read-timeout"
	HTTPReadHeaderTimeout = "http-read-header-timeout"
	HTTPWriteTimeout      = "http-write-timeout"

	PrometheusEnabled = "prometheus-enabled"
	PrometheusPath    = "prometheus-path"

	RateLimiterEnabled         = "ratelimiter-enabled"
	RateLimiterStoreKind       = "ratelimiter-store"
	RateLimiterMemoryRate      = "ratelimiter-memory-rate"
	RateLimiterMemoryBurst     = "ratelimiter-memory-burst"
	RateLimiterMemoryExpiresIn = "ratelimiter-memory-expires-in"

	RecoverEnabled             = "recover-enabled"
	RecoverStackSize           = "recover-stack-size"
	RecoverDisableStackAll     = "recover-disable-stack-all"
	RecoverDisablePrintStack   = "recover-disable-print-stack"
	RecoverDisableErrorHandler = "recover-disable-error-handler"

	RedirectHTTPS = "redirect-https"
	RedirectCode  = "redirect-code"

	RequestIDEnabled      = "requestid-enabled"
	RequestIDTargetHeader = "requestid-target-header"

	SecureEnabled                                  = "secure-enabled"
	SecureContentSecurityPolicy                    = "secure-content-security-policy"
	SecureContentSecurityPolicyReportOnly          = "secure-content-security-policy-report-only"
	SecureCrossOriginEmbedderPolicy                = "secure-cross-origin-embedder-policy"
	SecureCrossOriginOpenerPolicy                  = "secure-cross-origin-opener-policy"
	SecureCrossOriginResourcePolicy                = "secure-cross-origin-resource-policy"
	SecurePermissionsPolicy                        = "secure-permissions-policy"
	SecureReferrerPolicy                           = "secure-referrer-policy"
	SecureServer                                   = "secure-server"
	SecureStrictTransportSecurityMaxAge            = "secure-strict-transport-security-max-age"
	SecureStrictTransportSecurityExcludeSubdomains = "secure-strict-transport-security-exclude-subdomains"
	SecureStrictTransportSecurityPreloadEnabled    = "secure-strict-transport-security-preload-enabled"
	SecureXContentTypeOptions                      = "secure-x-content-type-options"
	SecureXFrameOptions                            = "secure-x-frame-options"

	SessionEnabled                 = "session-enabled"
	SessionStoreKind               = "session-store"
	SessionCookieSecret            = "session-cookie-secret"
	SessionRedisURI                = "session-redis-uri"
	SessionRedisClusterURI         = "session-redis-cluster-uri"
	SessionRedisSentinelMasterName = "session-redis-sentinel-master-name"
	SessionRedisSentinelAddrs      = "session-redis-sentinel-addrs"

	StaticEnabled    = "static-enabled"
	StaticRoot       = "static-root"
	StaticIndex      = "static-index"
	StaticHTML5      = "static-html5"
	StaticBrowse     = "static-browse"
	StaticIgnoreBase = "static-ignore-base"

	TimeoutEnabled      = "timeout-enabled"
	TimeoutErrorMessage = "timeout-error-message"
	TimeoutDuration     = "timeout-duration"

	TLSEnabled           = "tls-enabled"
	TLSBindAddr          = "tls-bind-addr"
	TLSCertFile          = "tls-cert-file"
	TLSKeyFile           = "tls-key-file"
	TLSACMEEnabled       = "tls-acme-enabled"
	TLSACMEEmail         = "tls-acme-email"
	TLSACMECachePath     = "tls-acme-cache-path"
	TLSACMEHostWhitelist = "tls-acme-host-whitelist"
	TLSACMEDirectoryURL  = "tls-acme-directory-url"
)

type FlagGroup struct {
	Name  string
	Desc  string
	Flags *pflag.FlagSet
}

// addFlags adds all the flags from the command line.
func (c *Config) addFlags(fs *pflag.FlagSet) {
	mainFlags := pflag.NewFlagSet("app", pflag.ExitOnError)
	mainFlags.SortFlags = false

	groups := []FlagGroup{
		{
			Desc: "Server configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Server", pflag.ExitOnError)
				groupFs.StringVar(&c.AppName, AppName, c.AppName, "Application name")
				groupFs.StringVar(&c.EnvName, EnvName, c.EnvName, "Environment name")
				groupFs.StringVar(&c.ConfigPrefix, ConfigPrefix, c.ConfigPrefix, "Sets the prefix for configuration files to be loaded, e.g., \"config\" would match \"config.{env_name}.toml\"")
				groupFs.StringVar(&c.ConfigType, ConfigType, c.ConfigType, "Defines the format of configuration files to be loaded\nValues: json, toml, or yaml")
				groupFs.StringSliceVar(&c.ConfigPaths, ConfigPaths, c.ConfigPaths, "Specifies directories where configuration files will be searched for, in order of preference")
				return groupFs
			}(),
		},
		{
			Desc:  "Logging configuration options",
			Flags: c.Logger.FlagSet(),
		},
		{
			Desc: "HTTP server configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("HTTP", pflag.ExitOnError)
				groupFs.StringVar(&c.Service.HTTP.BindAddr, HTTPBindAddr, c.Service.HTTP.BindAddr, "Specifies the host:port address for the HTTP server to listen on")
				groupFs.DurationVar(&c.Service.HTTP.GracefulTimeout, HTTPGracefulTimeout, c.Service.HTTP.GracefulTimeout, "Sets the maximum time to wait for in-flight requests to complete before shutting down the server")
				groupFs.BoolVar(&c.Service.HTTP.LogRequests, HTTPLogRequests, c.Service.HTTP.LogRequests, "Enables or disables logging of incoming HTTP requests")
				groupFs.DurationVar(&c.Service.HTTP.IdleTimeout, HTTPIdleTimeout, c.Service.HTTP.IdleTimeout, "Maximum duration to wait for the next request when keep-alives are enabled, a zero or negative value means there will be no timeout.")
				groupFs.DurationVar(&c.Service.HTTP.ReadTimeout, HTTPReadTimeout, c.Service.HTTP.ReadTimeout, "Maximum duration for reading the entire request, including the body, a zero or negative value means there will be no timeout")
				groupFs.DurationVar(&c.Service.HTTP.ReadHeaderTimeout, HTTPReadHeaderTimeout, c.Service.HTTP.ReadHeaderTimeout, "Maximum duration allowed for reading request headers, a zero or negative value means there will be no timeout")
				groupFs.DurationVar(&c.Service.HTTP.WriteTimeout, HTTPWriteTimeout, c.Service.HTTP.WriteTimeout, "Maximum duration before timing out writes of the response, a zero or negative value means there will be no timeout")
				return groupFs
			}(),
		},
		{
			Desc: "TLS configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("TLS", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.TLS.Enabled, TLSEnabled, c.Service.TLS.Enabled, "Enables TLS encryption for secure communications, when enabled, the server requires HTTPS connections")
				groupFs.StringVar(&c.Service.TLS.BindAddr, TLSBindAddr, c.Service.TLS.BindAddr, "Specifies the host:port address for the HTTPS server to listen on")
				groupFs.StringVar(&c.Service.TLS.CertFile, TLSCertFile, c.Service.TLS.CertFile, "Path to the TLS certificate file in PEM format containing the server's public key certificate")
				groupFs.StringVar(&c.Service.TLS.KeyFile, TLSKeyFile, c.Service.TLS.KeyFile, "Path to the TLS private key file in PEM format corresponding to the certificate")
				groupFs.BoolVar(&c.Service.TLS.ACME.Enabled, TLSACMEEnabled, c.Service.TLS.Enabled, "Enables automatic TLS certificate provisioning using the ACME protocol (Let's Encrypt)")
				groupFs.StringVar(&c.Service.TLS.ACME.Email, TLSACMEEmail, c.Service.TLS.ACME.Email, "Email address used for ACME account registration and certificate renewal notifications")
				groupFs.StringVar(&c.Service.TLS.ACME.CachePath, TLSACMECachePath, c.Service.TLS.ACME.CachePath, "Directory path where automatically provisioned TLS certificates will be stored")
				groupFs.StringSliceVar(&c.Service.TLS.ACME.HostWhitelist, TLSACMEHostWhitelist, c.Service.TLS.ACME.HostWhitelist, "List of hostnames allowed for automatic certificate provisioning")
				groupFs.StringVar(&c.Service.TLS.ACME.DirectoryURL, TLSACMEDirectoryURL, c.Service.TLS.ACME.DirectoryURL, "URL of the ACME directory endpoint to use (default is Let's Encrypt production; use https://acme-staging-v02.api.letsencrypt.org/directory for testing)")
				return groupFs
			}(),
		},
		{
			Desc: "Body limit middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Body Limit", pflag.ExitOnError)
				groupFs.StringVar(&c.Service.BodyLimit.Limit, BodyLimitLimit, c.Service.BodyLimit.Limit, "Sets the maximum allowed size of the request body, use values like \"100K\", \"10M\" or \"1G\"")
				return groupFs
			}(),
		},
		{
			Desc: "Compress middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Compress", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.Compress.Enabled, CompressEnabled, c.Service.Compress.Enabled, "Enable compression")
				groupFs.IntVar(&c.Service.Compress.Level, CompressLevel, c.Service.Compress.Level, "Compression level")
				groupFs.IntVar(&c.Service.Compress.MinLength, CompressMinLength, c.Service.Compress.MinLength, "Minimum response size in bytes before compression is applied")
				return groupFs
			}(),
		},
		{
			Desc: "CORS middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("CORS", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.CORS.Enabled, CORSEnabled, c.Service.CORS.Enabled, "Enable CORS middleware")
				groupFs.StringSliceVar(&c.Service.CORS.AllowOrigins, CORSAllowOrigins, c.Service.CORS.AllowOrigins, "Allowed origins for CORS requests")
				groupFs.StringSliceVar(&c.Service.CORS.AllowMethods, CORSAllowMethods, c.Service.CORS.AllowMethods, "Allowed HTTP methods in CORS request")
				groupFs.StringSliceVar(&c.Service.CORS.AllowHeaders, CORSAllowHeaders, c.Service.CORS.AllowHeaders, "Allowed headers in CORS requests")
				groupFs.BoolVar(&c.Service.CORS.AllowCredentials, CORSAllowCredentials, c.Service.CORS.AllowCredentials, "Allow credentials in CORS requests")
				groupFs.StringSliceVar(&c.Service.CORS.ExposeHeaders, CORSExposeHeaders, c.Service.CORS.ExposeHeaders, "Headers exposed to browsers in CORS responses")
				groupFs.IntVar(&c.Service.CORS.MaxAge, CORSMaxAge, c.Service.CORS.MaxAge, "Max age (in seconds) for CORS preflight responses")
				return groupFs
			}(),
		},
		{
			Desc: "CSRF middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("CSRF", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.CSRF.Enabled, CSRFEnabled, c.Service.CSRF.Enabled, "Enable CSRF protection middleware")
				groupFs.Uint8Var(&c.Service.CSRF.TokenLength, CSRFTokenLength, c.Service.CSRF.TokenLength, "Length of generated CSRF token in bytes")
				groupFs.StringVar(&c.Service.CSRF.TokenLookup, CSRFTokenLookup, c.Service.CSRF.TokenLookup, "Location to extract CSRF token from request")
				groupFs.StringVar(&c.Service.CSRF.ContextKey, CSRFContextKey, c.Service.CSRF.ContextKey, "Key used to store CSRF token in context")
				groupFs.StringVar(&c.Service.CSRF.CookieName, CSRFCookieName, c.Service.CSRF.CookieName, "Name of the CSRF cookie")
				groupFs.StringVar(&c.Service.CSRF.CookieDomain, CSRFCookieDomain, c.Service.CSRF.CookieDomain, "Domain attribute for CSRF cookie")
				groupFs.StringVar(&c.Service.CSRF.CookiePath, CSRFCookiePath, c.Service.CSRF.CookiePath, "Path attribute for CSRF cookie")
				groupFs.IntVar(&c.Service.CSRF.CookieMaxAge, CSRFCookieMaxAge, c.Service.CSRF.CookieMaxAge, "Maximum age in seconds for CSRF cookie ")
				groupFs.BoolVar(&c.Service.CSRF.CookieSecure, CSRFCookieSecure, c.Service.CSRF.CookieSecure, "Set Secure flag on CSRF cookie")
				groupFs.BoolVar(&c.Service.CSRF.CookieHTTPOnly, CSRFCookieHTTPOnly, c.Service.CSRF.CookieHTTPOnly, "Set HttpOnly flag on CSRF cookie")
				groupFs.Var(&c.Service.CSRF.CookieSameSite, CSRFCookieSameSite, fmt.Sprintf("SameSite attribute for CSRF cookie\nValues: %s", strings.Join(service.CSRFSameSiteModes, ", ")))
				return groupFs
			}(),
		},
		{
			Desc: "Healthcheck endpoints configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Healthcheck", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.Healthcheck.Enabled, HealthcheckEnabled, c.Service.Healthcheck.Enabled, "Enable health check endpoints")
				groupFs.StringVar(&c.Service.Healthcheck.LivenessEndpoint, HealthcheckLivenessEndpoint, c.Service.Healthcheck.LivenessEndpoint, "Path for the liveness health check endpoint that indicates if the application is running")
				groupFs.StringVar(&c.Service.Healthcheck.ReadinessEndpoint, HealthcheckReadinessEndpoint, c.Service.Healthcheck.ReadinessEndpoint, "Path for the readiness health check endpoint that indicates if the application is ready to receive traffic")
				groupFs.StringVar(&c.Service.Healthcheck.StartupEndpoint, HealthcheckStartupEndpoint, c.Service.Healthcheck.StartupEndpoint, "Path for the startup health check endpoint that indicates if the application has completed its initialization")
				return groupFs
			}(),
		},
		{
			Desc: "Prometheus configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Prometheus", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.Prometheus.Enabled, PrometheusEnabled, c.Service.Prometheus.Enabled, "Enables Prometheus metrics collection and exposure for application monitoring")
				groupFs.StringVar(&c.Service.Prometheus.Path, PrometheusPath, c.Service.Prometheus.Path, "Sets the HTTP path where Prometheus metrics will be exposed")
				return groupFs
			}(),
		},
		{
			Desc: "Rate limiter middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Rate Limiter", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.RateLimiter.Enabled, RateLimiterEnabled, c.Service.RateLimiter.Enabled, "Enable rate limiting middleware")
				groupFs.Var(&c.Service.RateLimiter.Store, RateLimiterStoreKind, fmt.Sprintf("Storage backend for rate limiting\nValues: %s", strings.Join(service.LimiterStores, ", ")))
				groupFs.Float64Var(&c.Service.RateLimiter.Memory.Rate, RateLimiterMemoryRate, c.Service.RateLimiter.Memory.Rate, "Maximum request rate per time window")
				groupFs.IntVar(&c.Service.RateLimiter.Memory.Burst, RateLimiterMemoryBurst, c.Service.RateLimiter.Memory.Burst, "Maximum number of requests allowed to exceed the rate")
				groupFs.DurationVar(&c.Service.RateLimiter.Memory.ExpiresIn, RateLimiterMemoryExpiresIn, c.Service.RateLimiter.Memory.ExpiresIn, "Time window for rate limit expiration")
				return groupFs
			}(),
		},
		{
			Desc: "Recover middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Recover", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.Recover.Enabled, RecoverEnabled, c.Service.Recover.Enabled, "Enable automatic recovery from panics")
				groupFs.IntVar(&c.Service.Recover.StackSize, RecoverStackSize, c.Service.Recover.StackSize, "Controls the size of the stack trace buffer in kilobytes that will be captured when a panic occurs")
				groupFs.BoolVar(&c.Service.Recover.DisableStackAll, RecoverDisableStackAll, c.Service.Recover.DisableStackAll, "Disables capturing the complete stack trace during panic recovery")
				groupFs.BoolVar(&c.Service.Recover.DisablePrintStack, RecoverDisablePrintStack, c.Service.Recover.DisablePrintStack, "Prevents printing the stack trace when recovering from panics")
				groupFs.BoolVar(&c.Service.Recover.DisableErrorHandler, RecoverDisableErrorHandler, c.Service.Recover.DisableErrorHandler, "Disables the default error handler for panics, allowing the application to crash instead of recovering")
				return groupFs
			}(),
		},
		{
			Desc: "Redirect configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Redirect", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.Redirect.HTTPS, RedirectHTTPS, c.Service.Redirect.HTTPS, "Controls whether HTTP requests are redirected to HTTPS")
				groupFs.IntVar(&c.Service.Redirect.Code, RedirectCode, c.Service.Redirect.Code, "Specifies the HTTP status code used for redirects")
				return groupFs
			}(),
		},
		{
			Desc: "Request ID middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Request ID", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.RequestID.Enabled, RequestIDEnabled, c.Service.RequestID.Enabled, "Enable request ID middleware")
				groupFs.StringVar(&c.Service.RequestID.TargetHeader, RequestIDTargetHeader, c.Service.RequestID.TargetHeader, "Custom header for request ID")
				return groupFs
			}(),
		},
		{
			Desc: "Security headers configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Secure", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.Secure.Enabled, SecureEnabled, c.Service.Secure.Enabled, "Enables all security headers for enhanced protection against common web vulnerabilities")
				groupFs.StringVar(&c.Service.Secure.ContentSecurityPolicy, SecureContentSecurityPolicy, c.Service.Secure.ContentSecurityPolicy, "Sets the Content-Security-Policy header to help prevent cross-site scripting and other code injection attacks")
				groupFs.BoolVar(&c.Service.Secure.ContentSecurityPolicyReportOnly, SecureContentSecurityPolicyReportOnly, c.Service.Secure.ContentSecurityPolicyReportOnly, "Enables report-only mode for CSP, which reports violations but doesn't enforce the policy")
				groupFs.StringVar(&c.Service.Secure.CrossOriginEmbedderPolicy, SecureCrossOriginEmbedderPolicy, c.Service.Secure.CrossOriginEmbedderPolicy, "Controls which cross-origin resources can be loaded, default \"require-corp\" only allows resources that explicitly grant permission")
				groupFs.StringVar(&c.Service.Secure.CrossOriginOpenerPolicy, SecureCrossOriginOpenerPolicy, c.Service.Secure.CrossOriginOpenerPolicy, "Controls window interactions between origins, default \"same-origin\" restricts interactions to same-origin documents only")
				groupFs.StringVar(&c.Service.Secure.CrossOriginResourcePolicy, SecureCrossOriginResourcePolicy, c.Service.Secure.CrossOriginResourcePolicy, "Specifies which origins can include your resources, default \"same-origin\" limits access to same-origin requests")
				groupFs.StringVar(&c.Service.Secure.PermissionsPolicy, SecurePermissionsPolicy, c.Service.Secure.PermissionsPolicy, "Controls which browser features and APIs can be used, default policy disables potentially sensitive features like camera, geolocation, and payment processing")
				groupFs.StringVar(&c.Service.Secure.ReferrerPolicy, SecureReferrerPolicy, c.Service.Secure.ReferrerPolicy, "Sets the Referrer-Policy header to control how much referrer information is included with requests")
				groupFs.StringVar(&c.Service.Secure.Server, SecureServer, c.Service.Secure.Server, "Sets a custom value for the HTTP Server header in responses")
				groupFs.IntVar(&c.Service.Secure.StrictTransportSecurity.MaxAge, SecureStrictTransportSecurityMaxAge, c.Service.Secure.StrictTransportSecurity.MaxAge, "Sets the max age in seconds for the HTTP Strict-Transport-Security (HSTS) header")
				groupFs.BoolVar(&c.Service.Secure.StrictTransportSecurity.ExcludeSubdomains, SecureStrictTransportSecurityExcludeSubdomains, c.Service.Secure.StrictTransportSecurity.ExcludeSubdomains, "Excludes subdomains from the HSTS policy, limiting it to the main domain only")
				groupFs.BoolVar(&c.Service.Secure.StrictTransportSecurity.PreloadEnabled, SecureStrictTransportSecurityPreloadEnabled, c.Service.Secure.StrictTransportSecurity.PreloadEnabled, "Adds the preload directive to the HSTS header, allowing the site to be included in browser preload lists")
				groupFs.StringVar(&c.Service.Secure.XContentTypeOptions, SecureXContentTypeOptions, c.Service.Secure.XContentTypeOptions, "Sets the X-Content-Type-Options header to prevent MIME type sniffing")
				groupFs.StringVar(&c.Service.Secure.XFrameOptions, SecureXFrameOptions, c.Service.Secure.XFrameOptions, "Sets the X-Frame-Options header to prevent clickjacking attacks")
				return groupFs
			}(),
		},
		{
			Desc: "Session middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Session", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.Session.Enabled, SessionEnabled, c.Service.Session.Enabled, "Enables session management for maintaining user state across requests")
				groupFs.Var(&c.Service.Session.Store, SessionStoreKind, fmt.Sprintf("Specifies the storage backend for session data\nValues: %s", strings.Join(service.SessionStores, ", ")))
				groupFs.StringVar(&c.Service.Session.Cookie.Secret, SessionCookieSecret, c.Service.Session.Cookie.Secret, "Sets the secret key used to sign and encrypt session cookies, this should be a strong, random value in production")
				groupFs.StringVar(&c.Service.Session.Redis.URI, SessionRedisURI, c.Service.Session.Redis.URI, "Specifies the URI for connecting to a standalone Redis server for session storage\nFormat: redis://[user:password@]host[:port][/database]")
				groupFs.StringVar(&c.Service.Session.RedisCluster.URI, SessionRedisClusterURI, c.Service.Session.RedisCluster.URI, "Specifies the URI for connecting to a Redis Cluster deployment for session storage, multiple nodes can be separated by commas")
				groupFs.StringVar(&c.Service.Session.RedisSentinel.MasterName, SessionRedisSentinelMasterName, c.Service.Session.RedisSentinel.MasterName, "Specifies the name of the master node in a Redis Sentinel configuration")
				groupFs.StringSliceVar(&c.Service.Session.RedisSentinel.SentinelAddrs, SessionRedisSentinelAddrs, c.Service.Session.RedisSentinel.SentinelAddrs, "Lists the addresses of Redis Sentinel nodes for high availability session storage")
				return groupFs
			}(),
		},
		{
			Desc: "Static file serving configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Static", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.Static.Enabled, StaticEnabled, c.Service.Static.Enabled, "Enables serving of static files from the specified directory")
				groupFs.StringVar(&c.Service.Static.Root, StaticRoot, c.Service.Static.Root, "Specifies the root directory from which to serve static files")
				groupFs.StringVar(&c.Service.Static.Index, StaticIndex, c.Service.Static.Index, "Sets the default file to serve when a directory is requested")
				groupFs.BoolVar(&c.Service.Static.HTML5, StaticHTML5, c.Service.Static.HTML5, "Enables HTML5 mode which redirects all not-found requests to index.html for single-page applications")
				groupFs.BoolVar(&c.Service.Static.Browse, StaticBrowse, c.Service.Static.Browse, "Enables directory browsing when no index file is present")
				groupFs.BoolVar(&c.Service.Static.IgnoreBase, StaticIgnoreBase, c.Service.Static.IgnoreBase, "Ignores the base path when serving static files, useful when your app is mounted under a sub-path")
				return groupFs
			}(),
		},
		{
			Desc: "Timeout middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Timeout", pflag.ExitOnError)
				groupFs.BoolVar(&c.Service.Timeout.Enabled, TimeoutEnabled, c.Service.Timeout.Enabled, "Enable request timeout middleware")
				groupFs.StringVar(&c.Service.Timeout.ErrorMessage, TimeoutErrorMessage, c.Service.Timeout.ErrorMessage, "Custom error message when request times out")
				groupFs.DurationVar(&c.Service.Timeout.Duration, TimeoutDuration, c.Service.Timeout.Duration, "Maximum duration allowed for request processing")
				return groupFs
			}(),
		},
	}

	for _, group := range groups {
		group.Flags.SortFlags = false
		mainFlags.AddFlagSet(group.Flags)
	}

	mainFlags.Usage = func() {
		binary := filepath.Base(os.Args[0])
		_, err := fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\n", binary)
		if err != nil {
			log.Err(err).Msg("failed writing to writer")
			return
		}

		w := tabwriter.NewWriter(os.Stderr, 0, 0, 3, ' ', 0)

		// Print each group
		for _, group := range groups {
			if group.Desc != "" {
				_, err := fmt.Fprintf(w, "%s:\n", group.Desc)
				if err != nil {
					log.Err(err).Msg("failed writing to writer")
					return
				}
			}

			// Inside the usage function, replace the flag printing part with this:
			group.Flags.VisitAll(func(flag *pflag.Flag) {
				// Format the default value
				defaultValue := ""
				if flag.DefValue != "" {
					defaultValue = fmt.Sprintf(" (default %s)", flag.DefValue)
				}

				// Format the shorthand
				shorthand := ""
				if flag.Shorthand != "" {
					shorthand = fmt.Sprintf("-%s, ", flag.Shorthand)
				}

				// Split the usage into lines
				usageLines := strings.Split(flag.Usage, "\n")

				typeName := flag.Value.Type()
				switch typeName {
				case "stringSlice":
					typeName = "strings"
				case "intSlice":
					typeName = "ints"
				}

				// Print the first line
				_, err := fmt.Fprintf(w, "  %s--%s %s\t%s%s\n",
					shorthand,
					flag.Name,
					typeName,
					usageLines[0],
					defaultValue)
				if err != nil {
					log.Err(err).Msg("failed writing to writer")
					return
				}

				// Print any additional lines, properly indented
				for _, line := range usageLines[1:] {
					_, err := fmt.Fprintf(w, "  \t%s\n", line)
					if err != nil {
						log.Err(err).Msg("failed writing to writer")
						return
					}
				}
			})
			_, err := fmt.Fprintln(w, "")
			if err != nil {
				log.Err(err).Msg("failed writing to writer")
				return
			}
		}

		err = w.Flush()
		if err != nil {
			log.Err(err).Msg("failed flushing writer")
			return
		}
	}

	// this is to remove:
	// pflag: help requested
	// exit status 2
	help := mainFlags.BoolP("help", "h", false, "Show help information")
	err := mainFlags.Parse(os.Args[1:])
	if err != nil {
		log.Err(err).Msg("failed parsing flags")
	}
	if *help {
		mainFlags.Usage()
		os.Exit(0)
	}

	fs.AddFlagSet(mainFlags)
}

// wordSepNormalizeFunc changes all flags that contain "_" separators.
func wordSepNormalizeFunc(_ *pflag.FlagSet, name string) pflag.NormalizedName {
	if strings.Contains(name, "_") {
		return pflag.NormalizedName(strings.ReplaceAll(name, "_", "-"))
	}
	return pflag.NormalizedName(name)
}

// BindFlags normalizes and parses the command line flags.
func (c *Config) BindFlags() error {
	if pflag.Parsed() {
		return nil
	}

	c.addFlags(pflag.CommandLine)
	err := viper.BindPFlags(pflag.CommandLine)
	if err != nil {
		return err
	}

	pflag.CommandLine.SetNormalizeFunc(wordSepNormalizeFunc)
	pflag.Parse()

	viper.SetEnvPrefix(viper.GetString(AppName))
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.AutomaticEnv()

	configName := fmt.Sprintf("%s.%s", viper.GetString(ConfigPrefix), strings.ToLower(viper.GetString(EnvName)))
	viper.SetConfigName(configName)
	viper.SetConfigType(viper.GetString(ConfigType))
	for _, path := range viper.GetStringSlice(ConfigPaths) {
		viper.AddConfigPath(path)
	}

	if err = viper.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			log.Warn().Err(err).Msg("config file not found")
		} else {
			log.Error().Err(err).Msg("failed reading in config")
		}
	}

	err = logger.New(&logger.Config{
		LogLevel:  viper.GetString(logger.LogLevel),
		LogOutput: viper.GetString(logger.LogOutput),
		LogFormat: viper.GetString(logger.LogFormat),
	})
	if err != nil {
		return fmt.Errorf("failed creating logger: %v", err)
	}

	if c.Service.Session.Enabled {
		if c.Service.Session.Cookie.Secret == service.DefaultSessionCookieSecret {
			log.Warn().Msg("session cookie secret using default value!")
		}
	}

	if c.Service.Timeout.Enabled {
		if c.Service.Timeout.Duration >= c.Service.HTTP.WriteTimeout {
			log.Warn().Msgf("timeout duration (%s) should be shorter than http write timeout (%s)", c.Service.Timeout.Duration, c.Service.HTTP.WriteTimeout)
		}
	}

	return nil
}
