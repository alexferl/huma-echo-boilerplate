package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/alexferl/huma-echo-boilerplate/healthcheck"
	"github.com/alexferl/huma-echo-boilerplate/logger"
)

// Config holds all global configuration for our program.
type Config struct {
	AppName         string
	EnvName         string
	ConfigPrefix    string
	ConfigType      string
	ConfigPaths     []string
	BindAddr        string
	GracefulTimeout time.Duration
	LogRequests     bool

	Logger      *logger.Config
	BodyLimit   BodyLimit
	Compress    Compress
	CORS        CORS
	CSRF        CSRF
	Healthcheck Healthcheck
	Prometheus  Prometheus
	RateLimiter RateLimiter
	Recover     Recover
	RequestID   RequestID
	Secure      Secure
	Session     Session
	Static      Static
	Timeout     Timeout
}

type BodyLimit struct {
	Limit string
}

type Compress struct {
	Enabled   bool
	Level     int
	MinLength int
}

type CORS struct {
	Enabled          bool
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	AllowCredentials bool
	ExposeHeaders    []string
	MaxAge           int
}

type CSRF struct {
	Enabled        bool
	TokenLength    uint8
	TokenLookup    string
	ContextKey     string
	CookieName     string
	CookieDomain   string
	CookiePath     string
	CookieMaxAge   int
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieSameSite CSRFSameSiteMode
}

type Healthcheck struct {
	Enabled           bool
	LivenessEndpoint  string
	ReadinessEndpoint string
	StartupEndpoint   string
}

type Prometheus struct {
	Enabled bool
	Path    string
}

type RateLimiter struct {
	Enabled bool
	Store   RateLimiterStore
	Memory  RateLimiterMemoryStore
}

type Recover struct {
	Enabled             bool
	StackSize           int
	DisableStackAll     bool
	DisablePrintStack   bool
	DisableErrorHandler bool
}

type RequestID struct {
	Enabled      bool
	TargetHeader string
}

type Secure struct {
	Enabled                         bool
	ContentSecurityPolicyReportOnly bool
	ContentSecurityPolicy           string
	ContentTypeNoSniff              string
	HSTSExcludeSubdomains           bool
	HSTSMaxAge                      int
	HSTSPreloadEnabled              bool
	ReferrerPolicy                  string
	XFrameOptions                   string
	XSSProtection                   string
}

type Session struct {
	Enabled       bool
	Store         SessionStore
	Cookie        SessionCookieStore
	Redis         SessionRedisStore
	RedisSentinel SessionRedisSentinelStore
	RedisCluster  SessionRedisClusterStore
}

type Static struct {
	Enabled    bool
	Root       string
	Index      string
	HTML5      bool
	Browse     bool
	IgnoreBase bool
}

type Timeout struct {
	Enabled      bool
	ErrorMessage string
	Timeout      time.Duration
}

// New creates a Config instance.
func New() *Config {
	return &Config{
		AppName:         "app",
		EnvName:         "local",
		ConfigPrefix:    "config",
		ConfigType:      "toml",
		ConfigPaths:     []string{"./configs", "/configs"},
		BindAddr:        "127.0.0.1:1323",
		GracefulTimeout: 30 * time.Second,
		LogRequests:     true,
		Logger:          logger.DefaultConfig,
		BodyLimit: BodyLimit{
			Limit: middleware.DefaultBodyLimitConfig.Limit,
		},
		Compress: Compress{
			Enabled:   true,
			Level:     6,
			MinLength: 1400,
		},
		CORS: CORS{
			Enabled:          false,
			AllowOrigins:     middleware.DefaultCORSConfig.AllowOrigins,
			AllowMethods:     middleware.DefaultCORSConfig.AllowMethods,
			AllowHeaders:     middleware.DefaultCORSConfig.AllowHeaders,
			AllowCredentials: middleware.DefaultCORSConfig.AllowCredentials,
			ExposeHeaders:    middleware.DefaultCORSConfig.ExposeHeaders,
			MaxAge:           middleware.DefaultCORSConfig.MaxAge,
		},
		CSRF: CSRF{
			Enabled:        false,
			TokenLength:    middleware.DefaultCSRFConfig.TokenLength,
			TokenLookup:    middleware.DefaultCSRFConfig.TokenLookup,
			ContextKey:     middleware.DefaultCSRFConfig.ContextKey,
			CookieName:     middleware.DefaultCSRFConfig.CookieName,
			CookieDomain:   middleware.DefaultCSRFConfig.CookieDomain,
			CookiePath:     middleware.DefaultCSRFConfig.CookiePath,
			CookieMaxAge:   middleware.DefaultCSRFConfig.CookieMaxAge,
			CookieHTTPOnly: middleware.DefaultCSRFConfig.CookieHTTPOnly,
			CookieSameSite: CSRFSameSiteMode(middleware.DefaultCSRFConfig.CookieSameSite),
		},
		Healthcheck: Healthcheck{
			Enabled:           false,
			LivenessEndpoint:  healthcheck.DefaultConfig.LivenessEndpoint,
			ReadinessEndpoint: healthcheck.DefaultConfig.ReadinessEndpoint,
			StartupEndpoint:   healthcheck.DefaultConfig.StartupEndpoint,
		},
		Prometheus: Prometheus{
			Enabled: false,
			Path:    "/metrics",
		},
		RateLimiter: RateLimiter{
			Enabled: false,
			Store:   LimiterStoreMemory,
			Memory: RateLimiterMemoryStore{
				Rate:      float64(middleware.DefaultRateLimiterMemoryStoreConfig.Rate),
				Burst:     middleware.DefaultRateLimiterMemoryStoreConfig.Burst,
				ExpiresIn: middleware.DefaultRateLimiterMemoryStoreConfig.ExpiresIn,
			},
		},
		Recover: Recover{
			Enabled:             true,
			StackSize:           middleware.DefaultRecoverConfig.StackSize,
			DisableStackAll:     middleware.DefaultRecoverConfig.DisableStackAll,
			DisablePrintStack:   middleware.DefaultRecoverConfig.DisablePrintStack,
			DisableErrorHandler: middleware.DefaultRecoverConfig.DisableErrorHandler,
		},
		RequestID: RequestID{
			Enabled:      true,
			TargetHeader: middleware.DefaultRequestIDConfig.TargetHeader,
		},
		Secure: Secure{
			Enabled:                         false,
			ContentSecurityPolicy:           middleware.DefaultSecureConfig.ContentSecurityPolicy,
			ContentSecurityPolicyReportOnly: middleware.DefaultSecureConfig.CSPReportOnly,
			ContentTypeNoSniff:              middleware.DefaultSecureConfig.ContentTypeNosniff,
			HSTSExcludeSubdomains:           middleware.DefaultSecureConfig.HSTSExcludeSubdomains,
			HSTSMaxAge:                      middleware.DefaultSecureConfig.HSTSMaxAge,
			HSTSPreloadEnabled:              middleware.DefaultSecureConfig.HSTSPreloadEnabled,
			ReferrerPolicy:                  middleware.DefaultSecureConfig.ReferrerPolicy,
			XFrameOptions:                   middleware.DefaultSecureConfig.XFrameOptions,
			XSSProtection:                   middleware.DefaultSecureConfig.XSSProtection,
		},
		Session: Session{
			Enabled: false,
			Store:   sessionStoreCookie,
			Cookie: SessionCookieStore{
				Secret: "changeme",
			},
			Redis: SessionRedisStore{
				URI: "redis://localhost:6379",
			},
			RedisSentinel: SessionRedisSentinelStore{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"localhost:6379"},
			},
			RedisCluster: SessionRedisClusterStore{
				URI: "redis://localhost:6379",
			},
		},
		Static: Static{
			Enabled:    false,
			Root:       middleware.DefaultStaticConfig.Root,
			Index:      middleware.DefaultStaticConfig.Index,
			HTML5:      middleware.DefaultStaticConfig.HTML5,
			Browse:     middleware.DefaultStaticConfig.Browse,
			IgnoreBase: middleware.DefaultStaticConfig.IgnoreBase,
		},
		Timeout: Timeout{
			Enabled:      false,
			ErrorMessage: middleware.DefaultTimeoutConfig.ErrorMessage,
			Timeout:      middleware.DefaultTimeoutConfig.Timeout,
		},
	}
}

const (
	AppName         = "app-name"
	EnvName         = "env-name"
	ConfigPrefix    = "config-prefix"
	ConfigType      = "config-type"
	ConfigPaths     = "config-paths"
	BindAddr        = "bind-addr"
	GracefulTimeout = "graceful-timeout"
	LogRequests     = "log-requests"

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

	RequestIDEnabled      = "requestid-enabled"
	RequestIDTargetHeader = "requestid-target-header"

	SecureEnabled                         = "secure-enabled"
	SecureContentSecurityPolicy           = "secure-content-security-policy"
	SecureContentSecurityPolicyReportOnly = "secure-content-security-policy-report-only"
	SecureContentTypeNoSniff              = "secure-content-type-no-sniff"
	SecureHSTSExcludeSubdomains           = "secure-hsts-exclude-subdomains"
	SecureHSTSMaxAge                      = "secure-hsts-max-age"
	SecureHSTSPreloadEnabled              = "secure-hsts-preload-enabled"
	SecureReferrerPolicy                  = "secure-referrer-policy"
	SecureXFrameOptions                   = "secure-x-frame-options"
	SecureXSSProtection                   = "secure-xss-protection"

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
	TimeoutTime         = "timeout-time"
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
				groupFs.StringVar(&c.BindAddr, BindAddr, c.BindAddr, "Server binding address")
				groupFs.DurationVar(&c.GracefulTimeout, GracefulTimeout, c.GracefulTimeout, "Sets the maximum time to wait for in-flight requests to complete before shutting down the server")
				groupFs.BoolVar(&c.LogRequests, LogRequests, c.LogRequests, "Enables or disables logging of incoming HTTP requests")
				return groupFs
			}(),
		},
		{
			Desc: "Body limit middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Body Limit", pflag.ExitOnError)
				groupFs.StringVar(&c.BodyLimit.Limit, BodyLimitLimit, c.BodyLimit.Limit, "Sets the maximum allowed size of the request body, use values like \"100K\", \"10M\" or \"1G\"")
				return groupFs
			}(),
		},
		{
			Desc: "Compress middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Compress", pflag.ExitOnError)
				groupFs.BoolVar(&c.Compress.Enabled, CompressEnabled, c.Compress.Enabled, "Enable compression")
				groupFs.IntVar(&c.Compress.Level, CompressLevel, c.Compress.Level, "Compression level")
				groupFs.IntVar(&c.Compress.MinLength, CompressMinLength, c.Compress.MinLength, "Minimum response size in bytes before compression is applied")
				return groupFs
			}(),
		},
		{
			Desc: "CORS middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("CORS", pflag.ExitOnError)
				groupFs.BoolVar(&c.CORS.Enabled, CORSEnabled, c.CORS.Enabled, "Enable CORS middleware")
				groupFs.StringSliceVar(&c.CORS.AllowOrigins, CORSAllowOrigins, c.CORS.AllowOrigins, "Allowed origins for CORS requests")
				groupFs.StringSliceVar(&c.CORS.AllowMethods, CORSAllowMethods, c.CORS.AllowMethods, "Allowed HTTP methods in CORS request")
				groupFs.StringSliceVar(&c.CORS.AllowHeaders, CORSAllowHeaders, c.CORS.AllowHeaders, "Allowed headers in CORS requests")
				groupFs.BoolVar(&c.CORS.AllowCredentials, CORSAllowCredentials, c.CORS.AllowCredentials, "Allow credentials in CORS requests")
				groupFs.StringSliceVar(&c.CORS.ExposeHeaders, CORSExposeHeaders, c.CORS.ExposeHeaders, "Headers exposed to browsers in CORS responses")
				groupFs.IntVar(&c.CORS.MaxAge, CORSMaxAge, c.CORS.MaxAge, "Max age (in seconds) for CORS preflight responses")
				return groupFs
			}(),
		},
		{
			Desc: "CSRF middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("CSRF", pflag.ExitOnError)
				groupFs.BoolVar(&c.CSRF.Enabled, CSRFEnabled, c.CSRF.Enabled, "Enable CSRF protection middleware")
				groupFs.Uint8Var(&c.CSRF.TokenLength, CSRFTokenLength, c.CSRF.TokenLength, "Length of generated CSRF token in bytes")
				groupFs.StringVar(&c.CSRF.TokenLookup, CSRFTokenLookup, c.CSRF.TokenLookup, "Location to extract CSRF token from request")
				groupFs.StringVar(&c.CSRF.ContextKey, CSRFContextKey, c.CSRF.ContextKey, "Key used to store CSRF token in context")
				groupFs.StringVar(&c.CSRF.CookieName, CSRFCookieName, c.CSRF.CookieName, "Name of the CSRF cookie")
				groupFs.StringVar(&c.CSRF.CookieDomain, CSRFCookieDomain, c.CSRF.CookieDomain, "Domain attribute for CSRF cookie")
				groupFs.StringVar(&c.CSRF.CookiePath, CSRFCookiePath, c.CSRF.CookiePath, "Path attribute for CSRF cookie")
				groupFs.IntVar(&c.CSRF.CookieMaxAge, CSRFCookieMaxAge, c.CSRF.CookieMaxAge, "Maximum age in seconds for CSRF cookie ")
				groupFs.BoolVar(&c.CSRF.CookieSecure, CSRFCookieSecure, c.CSRF.CookieSecure, "Set Secure flag on CSRF cookie")
				groupFs.BoolVar(&c.CSRF.CookieHTTPOnly, CSRFCookieHTTPOnly, c.CSRF.CookieHTTPOnly, "Set HttpOnly flag on CSRF cookie")
				groupFs.Var(&c.CSRF.CookieSameSite, CSRFCookieSameSite, fmt.Sprintf("SameSite attribute for CSRF cookie\nValues: %s", strings.Join(csrfSameSiteModes, ", ")))
				return groupFs
			}(),
		},
		{
			Desc: "Healthcheck endpoints configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Healthcheck", pflag.ExitOnError)
				groupFs.BoolVar(&c.Healthcheck.Enabled, HealthcheckEnabled, c.Healthcheck.Enabled, "Enable health check endpoints")
				groupFs.StringVar(&c.Healthcheck.LivenessEndpoint, HealthcheckLivenessEndpoint, c.Healthcheck.LivenessEndpoint, "Path for the liveness health check endpoint that indicates if the application is running")
				groupFs.StringVar(&c.Healthcheck.ReadinessEndpoint, HealthcheckReadinessEndpoint, c.Healthcheck.ReadinessEndpoint, "Path for the readiness health check endpoint that indicates if the application is ready to receive traffic")
				groupFs.StringVar(&c.Healthcheck.StartupEndpoint, HealthcheckStartupEndpoint, c.Healthcheck.StartupEndpoint, "Path for the startup health check endpoint that indicates if the application has completed its initialization")
				return groupFs
			}(),
		},
		{
			Desc:  "Logging configuration options",
			Flags: c.Logger.FlagSet(),
		},
		{
			Desc: "Prometheus configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Prometheus", pflag.ExitOnError)
				groupFs.BoolVar(&c.Prometheus.Enabled, PrometheusEnabled, c.Prometheus.Enabled, "Enables Prometheus metrics collection and exposure for application monitoring")
				groupFs.StringVar(&c.Prometheus.Path, PrometheusPath, c.Prometheus.Path, "Sets the HTTP path where Prometheus metrics will be exposed")
				return groupFs
			}(),
		},
		{
			Desc: "Rate limiter middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Rate Limiter", pflag.ExitOnError)
				groupFs.BoolVar(&c.RateLimiter.Enabled, RateLimiterEnabled, c.RateLimiter.Enabled, "Enable rate limiting middleware")
				groupFs.Var(&c.RateLimiter.Store, RateLimiterStoreKind, fmt.Sprintf("Storage backend for rate limiting\nValues: %s", strings.Join(limiterStores, ", ")))
				groupFs.Float64Var(&c.RateLimiter.Memory.Rate, RateLimiterMemoryRate, c.RateLimiter.Memory.Rate, "Maximum request rate per time window")
				groupFs.IntVar(&c.RateLimiter.Memory.Burst, RateLimiterMemoryBurst, c.RateLimiter.Memory.Burst, "Maximum number of requests allowed to exceed the rate")
				groupFs.DurationVar(&c.RateLimiter.Memory.ExpiresIn, RateLimiterMemoryExpiresIn, c.RateLimiter.Memory.ExpiresIn, "Time window for rate limit expiration")
				return groupFs
			}(),
		},
		{
			Desc: "Recover middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Recover", pflag.ExitOnError)
				groupFs.BoolVar(&c.Recover.Enabled, RecoverEnabled, c.Recover.Enabled, "Enable automatic recovery from panics")
				groupFs.IntVar(&c.Recover.StackSize, RecoverStackSize, c.Recover.StackSize, "recover")
				groupFs.BoolVar(&c.Recover.DisableStackAll, RecoverDisableStackAll, c.Recover.DisableStackAll, "Disables capturing the complete stack trace during panic recovery")
				groupFs.BoolVar(&c.Recover.DisablePrintStack, RecoverDisablePrintStack, c.Recover.DisablePrintStack, "Prevents printing the stack trace when recovering from panics")
				groupFs.BoolVar(&c.Recover.DisableErrorHandler, RecoverDisableErrorHandler, c.Recover.DisableErrorHandler, "Disables the default error handler for panics, allowing the application to crash instead of recovering")
				return groupFs
			}(),
		},
		{
			Desc: "Request ID middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Request ID", pflag.ExitOnError)
				groupFs.BoolVar(&c.RequestID.Enabled, RequestIDEnabled, c.RequestID.Enabled, "Enable request ID middleware")
				groupFs.StringVar(&c.RequestID.TargetHeader, RequestIDTargetHeader, c.RequestID.TargetHeader, "Custom header for request ID")
				return groupFs
			}(),
		},
		{
			Desc: "Security headers configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Secure", pflag.ExitOnError)
				groupFs.BoolVar(&c.Secure.Enabled, SecureEnabled, c.Secure.Enabled, "Enables all security headers for enhanced protection against common web vulnerabilities")
				groupFs.StringVar(&c.Secure.ContentSecurityPolicy, SecureContentSecurityPolicy, c.Secure.ContentSecurityPolicy, "Sets the Content-Security-Policy header to help prevent cross-site scripting and other code injection attacks")
				groupFs.BoolVar(&c.Secure.ContentSecurityPolicyReportOnly, SecureContentSecurityPolicyReportOnly, c.Secure.ContentSecurityPolicyReportOnly, "Enables report-only mode for CSP, which reports violations but doesn't enforce the policy")
				groupFs.StringVar(&c.Secure.ContentTypeNoSniff, SecureContentTypeNoSniff, c.Secure.ContentTypeNoSniff, "Sets the X-Content-Type-Options header to prevent MIME type sniffing")
				groupFs.BoolVar(&c.Secure.HSTSExcludeSubdomains, SecureHSTSExcludeSubdomains, c.Secure.HSTSExcludeSubdomains, "Excludes subdomains from the HSTS policy, limiting it to the main domain only")
				groupFs.IntVar(&c.Secure.HSTSMaxAge, SecureHSTSMaxAge, c.Secure.HSTSMaxAge, "Sets the max age in seconds for the Strict-Transport-Security header")
				groupFs.BoolVar(&c.Secure.HSTSPreloadEnabled, SecureHSTSPreloadEnabled, c.Secure.HSTSPreloadEnabled, "Adds the preload directive to the HSTS header, allowing the site to be included in browser preload lists")
				groupFs.StringVar(&c.Secure.ReferrerPolicy, SecureReferrerPolicy, c.Secure.ReferrerPolicy, "Sets the Referrer-Policy header to control how much referrer information is included with requests")
				groupFs.StringVar(&c.Secure.XFrameOptions, SecureXFrameOptions, c.Secure.XFrameOptions, "Sets the X-Frame-Options header to prevent clickjacking attacks")
				groupFs.StringVar(&c.Secure.XSSProtection, SecureXSSProtection, c.Secure.XSSProtection, "Sets the X-XSS-Protection header to enable browser's built-in XSS filtering")
				return groupFs
			}(),
		},
		{
			Desc: "Session middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Session", pflag.ExitOnError)
				groupFs.BoolVar(&c.Session.Enabled, SessionEnabled, c.Session.Enabled, "Enables session management for maintaining user state across requests")
				groupFs.Var(&c.Session.Store, SessionStoreKind, fmt.Sprintf("Specifies the storage backend for session data\nValues: %s", strings.Join(sessionStores, ", ")))
				groupFs.StringVar(&c.Session.Cookie.Secret, SessionCookieSecret, c.Session.Cookie.Secret, "Sets the secret key used to sign and encrypt session cookies, this should be a strong, random value in production")
				groupFs.StringVar(&c.Session.Redis.URI, SessionRedisURI, c.Session.Redis.URI, "Specifies the URI for connecting to a standalone Redis server for session storage\nFormat: redis://[user:password@]host[:port][/database]")
				groupFs.StringVar(&c.Session.RedisCluster.URI, SessionRedisClusterURI, c.Session.RedisCluster.URI, "Specifies the URI for connecting to a Redis Cluster deployment for session storage, multiple nodes can be separated by commas")
				groupFs.StringVar(&c.Session.RedisSentinel.MasterName, SessionRedisSentinelMasterName, c.Session.RedisSentinel.MasterName, "Specifies the name of the master node in a Redis Sentinel configuration")
				groupFs.StringSliceVar(&c.Session.RedisSentinel.SentinelAddrs, SessionRedisSentinelAddrs, c.Session.RedisSentinel.SentinelAddrs, "Lists the addresses of Redis Sentinel nodes for high availability session storage")
				return groupFs
			}(),
		},
		{
			Desc: "Static file serving configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Static", pflag.ExitOnError)
				groupFs.BoolVar(&c.Static.Enabled, StaticEnabled, c.Static.Enabled, "Enables serving of static files from the specified directory")
				groupFs.StringVar(&c.Static.Root, StaticRoot, c.Static.Root, "Specifies the root directory from which to serve static files")
				groupFs.StringVar(&c.Static.Index, StaticIndex, c.Static.Index, "Sets the default file to serve when a directory is requested")
				groupFs.BoolVar(&c.Static.HTML5, StaticHTML5, c.Static.HTML5, "Enables HTML5 mode which redirects all not-found requests to index.html for single-page applications")
				groupFs.BoolVar(&c.Static.Browse, StaticBrowse, c.Static.Browse, "Enables directory browsing when no index file is present")
				groupFs.BoolVar(&c.Static.IgnoreBase, StaticIgnoreBase, c.Static.IgnoreBase, "Ignores the base path when serving static files, useful when your app is mounted under a sub-path")
				return groupFs
			}(),
		},
		{
			Desc: "Timeout middleware configuration options",
			Flags: func() *pflag.FlagSet {
				groupFs := pflag.NewFlagSet("Timeout", pflag.ExitOnError)
				groupFs.BoolVar(&c.Timeout.Enabled, TimeoutEnabled, c.Timeout.Enabled, "Enable request timeout middleware")
				groupFs.StringVar(&c.Timeout.ErrorMessage, TimeoutErrorMessage, c.Timeout.ErrorMessage, "Custom error message when request times out")
				groupFs.DurationVar(&c.Timeout.Timeout, TimeoutTime, c.Timeout.Timeout, "Maximum duration allowed for request processing")
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

	return nil
}
