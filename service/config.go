package service

import (
	"time"

	secure "github.com/alexferl/echo-secure"
	"github.com/labstack/echo/v4/middleware"

	"github.com/alexferl/huma-echo-boilerplate/healthcheck"
)

const (
	DefaultSessionCookieSecret = "changeme"
)

type Config struct {
	Name        string
	BodyLimit   BodyLimit
	Compress    Compress
	CORS        CORS
	CSRF        CSRF
	Healthcheck Healthcheck
	HTTP        HTTP
	Prometheus  Prometheus
	RateLimiter RateLimiter
	Recover     Recover
	Redirect    Redirect
	RequestID   RequestID
	Secure      Secure
	Session     Session
	Static      Static
	Timeout     Timeout
	TLS         TLS
}

type BodyLimit struct {
	Enabled bool
	Limit   string
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

type HTTP struct {
	BindAddr          string
	GracefulTimeout   time.Duration
	LogRequests       bool
	IdleTimeout       time.Duration
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
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

type Redirect struct {
	HTTPS bool
	Code  int
}

type RequestID struct {
	Enabled      bool
	TargetHeader string
}

type StrictTransportSecurity struct {
	MaxAge            int
	ExcludeSubdomains bool
	PreloadEnabled    bool
}

type Secure struct {
	Enabled                         bool
	ContentSecurityPolicy           string
	ContentSecurityPolicyReportOnly bool
	CrossOriginEmbedderPolicy       string
	CrossOriginOpenerPolicy         string
	CrossOriginResourcePolicy       string
	PermissionsPolicy               string
	ReferrerPolicy                  string
	Server                          string
	StrictTransportSecurity         StrictTransportSecurity
	XContentTypeOptions             string
	XFrameOptions                   string
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
	Duration     time.Duration
}

type TLS struct {
	Enabled  bool
	BindAddr string
	CertFile string
	KeyFile  string
	ACME     TLSACME
}

type TLSACME struct {
	Enabled       bool
	Email         string
	CachePath     string
	HostWhitelist []string
	DirectoryURL  string
}

var DefaultConfig = Config{
	BodyLimit: BodyLimit{
		Enabled: true,
		Limit:   "1MB",
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
	HTTP: HTTP{
		BindAddr:          "localhost:8080",
		GracefulTimeout:   30 * time.Second,
		LogRequests:       true,
		IdleTimeout:       time.Minute,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      30 * time.Second,
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
	Redirect: Redirect{
		HTTPS: false,
		Code:  middleware.DefaultRedirectConfig.Code,
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
		ContentSecurityPolicy:           secure.DefaultConfig.ContentSecurityPolicy,
		ContentSecurityPolicyReportOnly: secure.DefaultConfig.ContentSecurityPolicyReportOnly,
		CrossOriginEmbedderPolicy:       secure.DefaultConfig.CrossOriginEmbedderPolicy,
		CrossOriginOpenerPolicy:         secure.DefaultConfig.CrossOriginOpenerPolicy,
		CrossOriginResourcePolicy:       secure.DefaultConfig.CrossOriginResourcePolicy,
		PermissionsPolicy:               secure.DefaultConfig.PermissionsPolicy,
		ReferrerPolicy:                  secure.DefaultConfig.ReferrerPolicy,
		Server:                          secure.DefaultConfig.Server,
		StrictTransportSecurity: StrictTransportSecurity{
			MaxAge:            secure.DefaultConfig.StrictTransportSecurity.MaxAge,
			ExcludeSubdomains: secure.DefaultConfig.StrictTransportSecurity.ExcludeSubdomains,
			PreloadEnabled:    secure.DefaultConfig.StrictTransportSecurity.PreloadEnabled,
		},
		XContentTypeOptions: secure.DefaultConfig.XContentTypeOptions,
		XFrameOptions:       secure.DefaultConfig.XFrameOptions,
	},
	Session: Session{
		Enabled: false,
		Store:   sessionStoreCookie,
		Cookie: SessionCookieStore{
			Secret: DefaultSessionCookieSecret,
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
		ErrorMessage: "Request timeout",
		Duration:     15 * time.Second,
	},
	TLS: TLS{
		Enabled:  false,
		BindAddr: "localhost:8443",
		CertFile: "",
		KeyFile:  "",
		ACME: TLSACME{
			Enabled:       false,
			Email:         "",
			CachePath:     "./certs",
			HostWhitelist: []string{},
			DirectoryURL:  "",
		},
	},
}
