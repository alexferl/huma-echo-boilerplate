package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

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
	CORS        CORS
	CSRF        CSRF
	GZIP        GZIP
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

type GZIP struct {
	Enabled   bool
	Level     int
	MinLength int
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
		GZIP: GZIP{
			Enabled:   false,
			Level:     middleware.DefaultGzipConfig.Level,
			MinLength: middleware.DefaultGzipConfig.MinLength,
		},
		Healthcheck: Healthcheck{
			Enabled: true,
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
			Enabled:      true,
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

	GZIPEnabled   = "gzip-enabled"
	GZIPLevel     = "gzip-level"
	GZIPMinLength = "gzip-min-length"

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

// addFlags adds all the flags from the command line.
func (c *Config) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&c.AppName, AppName, c.AppName, "Application name")
	fs.StringVar(&c.EnvName, EnvName, c.EnvName, "Environment name")
	fs.StringVar(&c.ConfigPrefix, ConfigPrefix, c.ConfigPrefix, "Sets the prefix for configuration files to be loaded, e.g., \"config\" would match \"config.{env_name}.toml\"")
	fs.StringVar(&c.ConfigType, ConfigType, c.ConfigType, "Defines the format of configuration files to be loaded\nValues: json, toml, or yaml")
	fs.StringSliceVar(&c.ConfigPaths, ConfigPaths, c.ConfigPaths, "Specifies directories where configuration files will be searched for, in order of preference")
	fs.StringVar(&c.BindAddr, BindAddr, c.BindAddr, "Server binding address")
	fs.DurationVar(&c.GracefulTimeout, GracefulTimeout, c.GracefulTimeout, "timeout")
	fs.BoolVar(&c.LogRequests, LogRequests, c.LogRequests, "Enables or disables logging of incoming HTTP requests")

	fs.StringVar(&c.BodyLimit.Limit, BodyLimitLimit, c.BodyLimit.Limit, "Sets the maximum allowed size of the request body, use values like \"100K\", \"10M\" or \"1G\"")

	fs.BoolVar(&c.CORS.Enabled, CORSEnabled, c.CORS.Enabled, "Enable CORS middleware")
	fs.StringSliceVar(&c.CORS.AllowOrigins, CORSAllowOrigins, c.CORS.AllowOrigins, "Allowed origins for CORS requests")
	fs.StringSliceVar(&c.CORS.AllowMethods, CORSAllowMethods, c.CORS.AllowMethods, "Allowed HTTP methods in CORS request")
	fs.StringSliceVar(&c.CORS.AllowHeaders, CORSAllowHeaders, c.CORS.AllowHeaders, "Allowed headers in CORS requests")
	fs.BoolVar(&c.CORS.AllowCredentials, CORSAllowCredentials, c.CORS.AllowCredentials, "Allow credentials in CORS requests")
	fs.StringSliceVar(&c.CORS.ExposeHeaders, CORSExposeHeaders, c.CORS.ExposeHeaders, "Headers exposed to browsers in CORS responses")
	fs.IntVar(&c.CORS.MaxAge, CORSMaxAge, c.CORS.MaxAge, "Max age (in seconds) for CORS preflight responses")

	fs.BoolVar(&c.CSRF.Enabled, CSRFEnabled, c.CSRF.Enabled, "Enable CSRF protection middleware")
	fs.Uint8Var(&c.CSRF.TokenLength, CSRFTokenLength, c.CSRF.TokenLength, "Length of generated CSRF token in bytes")
	fs.StringVar(&c.CSRF.TokenLookup, CSRFTokenLookup, c.CSRF.TokenLookup, "Location to extract CSRF token from request")
	fs.StringVar(&c.CSRF.ContextKey, CSRFContextKey, c.CSRF.ContextKey, "Key used to store CSRF token in context")
	fs.StringVar(&c.CSRF.CookieName, CSRFCookieName, c.CSRF.CookieName, "Name of the CSRF cookie")
	fs.StringVar(&c.CSRF.CookieDomain, CSRFCookieDomain, c.CSRF.CookieDomain, "Domain attribute for CSRF cookie")
	fs.StringVar(&c.CSRF.CookiePath, CSRFCookiePath, c.CSRF.CookiePath, "Path attribute for CSRF cookie")
	fs.IntVar(&c.CSRF.CookieMaxAge, CSRFCookieMaxAge, c.CSRF.CookieMaxAge, "Maximum age in seconds for CSRF cookie ")
	fs.BoolVar(&c.CSRF.CookieSecure, CSRFCookieSecure, c.CSRF.CookieSecure, "Set Secure flag on CSRF cookie")
	fs.BoolVar(&c.CSRF.CookieHTTPOnly, CSRFCookieHTTPOnly, c.CSRF.CookieHTTPOnly, "Set HttpOnly flag on CSRF cookie")
	fs.Var(&c.CSRF.CookieSameSite, CSRFCookieSameSite, fmt.Sprintf("SameSite attribute for CSRF cookie\nValues: %s", strings.Join(csrfSameSiteModes, ", ")))

	fs.BoolVar(&c.GZIP.Enabled, GZIPEnabled, c.GZIP.Enabled, "Enable GZIP compression")
	fs.IntVar(&c.GZIP.Level, GZIPLevel, c.GZIP.Level, "Compression level")
	fs.IntVar(&c.GZIP.MinLength, GZIPMinLength, c.GZIP.MinLength, "Minimum response size in bytes before compression is applied")

	fs.BoolVar(&c.Healthcheck.Enabled, HealthcheckEnabled, c.Healthcheck.Enabled, "Enable health check endpoints")
	fs.StringVar(&c.Healthcheck.LivenessEndpoint, HealthcheckLivenessEndpoint, c.Healthcheck.LivenessEndpoint, "Path for the liveness health check endpoint that indicates if the application is running")
	fs.StringVar(&c.Healthcheck.ReadinessEndpoint, HealthcheckReadinessEndpoint, c.Healthcheck.ReadinessEndpoint, "Path for the readiness health check endpoint that indicates if the application is ready to receive traffic")
	fs.StringVar(&c.Healthcheck.StartupEndpoint, HealthcheckStartupEndpoint, c.Healthcheck.StartupEndpoint, "Path for the startup health check endpoint that indicates if the application has completed its initialization")

	fs.BoolVar(&c.Prometheus.Enabled, PrometheusEnabled, c.Prometheus.Enabled, "Enables Prometheus metrics collection and exposure for application monitoring")
	fs.StringVar(&c.Prometheus.Path, PrometheusPath, c.Prometheus.Path, "Sets the HTTP path where Prometheus metrics will be exposed")

	fs.BoolVar(&c.RateLimiter.Enabled, RateLimiterEnabled, c.RateLimiter.Enabled, "Enable rate limiting middleware")
	fs.Var(&c.RateLimiter.Store, RateLimiterStoreKind, fmt.Sprintf("Storage backend for rate limiting\nValues: %s", strings.Join(limiterStores, ", ")))
	fs.Float64Var(&c.RateLimiter.Memory.Rate, RateLimiterMemoryRate, c.RateLimiter.Memory.Rate, "Maximum request rate per time window")
	fs.IntVar(&c.RateLimiter.Memory.Burst, RateLimiterMemoryBurst, c.RateLimiter.Memory.Burst, "Maximum number of requests allowed to exceed the rate")
	fs.DurationVar(&c.RateLimiter.Memory.ExpiresIn, RateLimiterMemoryExpiresIn, c.RateLimiter.Memory.ExpiresIn, "Time window for rate limit expiration")

	fs.BoolVar(&c.Recover.Enabled, RecoverEnabled, c.Recover.Enabled, "Enable automatic recovery from panics")
	fs.IntVar(&c.Recover.StackSize, RecoverStackSize, c.Recover.StackSize, "recover")
	fs.BoolVar(&c.Recover.DisableStackAll, RecoverDisableStackAll, c.Recover.DisableStackAll, "Disables capturing the complete stack trace during panic recovery")
	fs.BoolVar(&c.Recover.DisablePrintStack, RecoverDisablePrintStack, c.Recover.DisablePrintStack, "Prevents printing the stack trace when recovering from panics")
	fs.BoolVar(&c.Recover.DisableErrorHandler, RecoverDisableErrorHandler, c.Recover.DisableErrorHandler, "Disables the default error handler for panics, allowing the application to crash instead of recovering")

	fs.BoolVar(&c.RequestID.Enabled, RequestIDEnabled, c.RequestID.Enabled, "Enable request ID middleware")
	fs.StringVar(&c.RequestID.TargetHeader, RequestIDTargetHeader, c.RequestID.TargetHeader, "Custom header for request ID")

	fs.BoolVar(&c.Secure.Enabled, SecureEnabled, c.Secure.Enabled, "Enables all security headers for enhanced protection against common web vulnerabilities")
	fs.StringVar(&c.Secure.ContentSecurityPolicy, SecureContentSecurityPolicy, c.Secure.ContentSecurityPolicy, "Sets the Content-Security-Policy header to help prevent cross-site scripting and other code injection attacks")
	fs.BoolVar(&c.Secure.ContentSecurityPolicyReportOnly, SecureContentSecurityPolicyReportOnly, c.Secure.ContentSecurityPolicyReportOnly, "Enables report-only mode for CSP, which reports violations but doesn't enforce the policy")
	fs.StringVar(&c.Secure.ContentTypeNoSniff, SecureContentTypeNoSniff, c.Secure.ContentTypeNoSniff, "Sets the X-Content-Type-Options header to prevent MIME type sniffing")
	fs.BoolVar(&c.Secure.HSTSExcludeSubdomains, SecureHSTSExcludeSubdomains, c.Secure.HSTSExcludeSubdomains, "Excludes subdomains from the HSTS policy, limiting it to the main domain only")
	fs.IntVar(&c.Secure.HSTSMaxAge, SecureHSTSMaxAge, c.Secure.HSTSMaxAge, "Sets the max age in seconds for the Strict-Transport-Security header")
	fs.BoolVar(&c.Secure.HSTSPreloadEnabled, SecureHSTSPreloadEnabled, c.Secure.HSTSPreloadEnabled, "Adds the preload directive to the HSTS header, allowing the site to be included in browser preload lists")
	fs.StringVar(&c.Secure.ReferrerPolicy, SecureReferrerPolicy, c.Secure.ReferrerPolicy, "Sets the Referrer-Policy header to control how much referrer information is included with requests")
	fs.StringVar(&c.Secure.XFrameOptions, SecureXFrameOptions, c.Secure.XFrameOptions, "Sets the X-Frame-Options header to prevent clickjacking attacks")
	fs.StringVar(&c.Secure.XSSProtection, SecureXSSProtection, c.Secure.XSSProtection, "Sets the X-XSS-Protection header to enable browser's built-in XSS filtering")

	fs.BoolVar(&c.Session.Enabled, SessionEnabled, c.Session.Enabled, "Enables session management for maintaining user state across requests")
	fs.Var(&c.Session.Store, SessionStoreKind, fmt.Sprintf("Specifies the storage backend for session data\nValues: %s", strings.Join(sessionStores, ", ")))
	fs.StringVar(&c.Session.Cookie.Secret, SessionCookieSecret, c.Session.Cookie.Secret, "Sets the secret key used to sign and encrypt session cookies, this should be a strong, random value in production")
	fs.StringVar(&c.Session.Redis.URI, SessionRedisURI, c.Session.Redis.URI, "Specifies the URI for connecting to a standalone Redis server for session storage\nFormat: redis://[user:password@]host[:port][/database]")
	fs.StringVar(&c.Session.RedisCluster.URI, SessionRedisClusterURI, c.Session.RedisCluster.URI, "Specifies the URI for connecting to a Redis Cluster deployment for session storage, multiple nodes can be separated by commas")
	fs.StringVar(&c.Session.RedisSentinel.MasterName, SessionRedisSentinelMasterName, c.Session.RedisSentinel.MasterName, "Specifies the name of the master node in a Redis Sentinel configuration")
	fs.StringSliceVar(&c.Session.RedisSentinel.SentinelAddrs, SessionRedisSentinelAddrs, c.Session.RedisSentinel.SentinelAddrs, "Lists the addresses of Redis Sentinel nodes for high availability session storage")

	fs.BoolVar(&c.Static.Enabled, StaticEnabled, c.Static.Enabled, "Enables serving of static files from the specified directory")
	fs.StringVar(&c.Static.Root, StaticRoot, c.Static.Root, "Specifies the root directory from which to serve static files")
	fs.StringVar(&c.Static.Index, StaticIndex, c.Static.Index, "Sets the default file to serve when a directory is requested")
	fs.BoolVar(&c.Static.HTML5, StaticHTML5, c.Static.HTML5, "Enables HTML5 mode which redirects all not-found requests to index.html for single-page applications")
	fs.BoolVar(&c.Static.Browse, StaticBrowse, c.Static.Browse, "Enables directory browsing when no index file is present")
	fs.BoolVar(&c.Static.IgnoreBase, StaticIgnoreBase, c.Static.IgnoreBase, "Ignores the base path when serving static files, useful when your app is mounted under a sub-path")

	fs.BoolVar(&c.Timeout.Enabled, TimeoutEnabled, c.Timeout.Enabled, "Enable request timeout middleware")
	fs.StringVar(&c.Timeout.ErrorMessage, TimeoutErrorMessage, c.Timeout.ErrorMessage, "Custom error message when request times out")
	fs.DurationVar(&c.Timeout.Timeout, TimeoutTime, c.Timeout.Timeout, "Maximum duration allowed for request processing")
}

// wordSepNormalizeFunc changes all flags that contain "_" separators.
func wordSepNormalizeFunc(_ *pflag.FlagSet, name string) pflag.NormalizedName {
	if strings.Contains(name, "_") {
		return pflag.NormalizedName(strings.ReplaceAll(name, "_", "-"))
	}
	return pflag.NormalizedName(name)
}

// BindFlags normalizes and parses the command line flags.
func (c *Config) BindFlags(flagSets ...func(fs *pflag.FlagSet)) error {
	if pflag.Parsed() {
		return nil
	}

	for _, flagSet := range flagSets {
		flagSet(pflag.CommandLine)
	}

	c.addFlags(pflag.CommandLine)
	c.Logger.BindFlags(pflag.CommandLine)
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
		LogWriter: viper.GetString(logger.LogWriter),
	})
	if err != nil {
		return fmt.Errorf("failed creating logger: %v", err)
	}

	return nil
}
