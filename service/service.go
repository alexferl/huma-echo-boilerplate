package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	secure "github.com/alexferl/echo-secure"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humaecho"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rbcervilla/redisstore/v9"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
	"github.com/ziflex/lecho/v3"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/time/rate"

	app "github.com/alexferl/huma-echo-boilerplate"
	"github.com/alexferl/huma-echo-boilerplate/service/healthcheck"
)

type echoCtxKey struct{}

type Service struct {
	cfg         Config
	e           *echo.Echo
	httpServer  *http.Server
	httpsServer *http.Server
	errCh       chan error
	ctx         context.Context
	cancel      context.CancelFunc
}

func New(cfg Config) (*Service, error) {
	ctx, cancel := context.WithCancel(context.Background())

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Logger = lecho.From(log.Logger)

	srv := &Service{
		cfg:    cfg,
		e:      e,
		errCh:  make(chan error, 10),
		ctx:    ctx,
		cancel: cancel,
	}

	var middlewares []echo.MiddlewareFunc

	// needs to be first
	if cfg.Timeout.Enabled {
		middlewares = append(middlewares, middleware.TimeoutWithConfig(middleware.TimeoutConfig{
			ErrorMessage: cfg.Timeout.ErrorMessage,
			Timeout:      cfg.Timeout.Duration,
		}))
	}

	if cfg.BodyLimit.Enabled {
		middlewares = append(middlewares, middleware.BodyLimitWithConfig(middleware.BodyLimitConfig{
			Limit: cfg.BodyLimit.Limit,
		}))
	}

	if cfg.CORS.Enabled {
		middlewares = append(middlewares, middleware.CORSWithConfig(middleware.CORSConfig{
			AllowOrigins:     cfg.CORS.AllowOrigins,
			AllowMethods:     cfg.CORS.AllowMethods,
			AllowHeaders:     cfg.CORS.AllowHeaders,
			AllowCredentials: cfg.CORS.AllowCredentials,
			ExposeHeaders:    cfg.CORS.ExposeHeaders,
			MaxAge:           cfg.CORS.MaxAge,
		}))
	}

	if cfg.CSRF.Enabled {
		middlewares = append(middlewares, middleware.CSRFWithConfig(middleware.CSRFConfig{
			TokenLength:    cfg.CSRF.TokenLength,
			TokenLookup:    cfg.CSRF.TokenLookup,
			ContextKey:     cfg.CSRF.ContextKey,
			CookieName:     cfg.CSRF.CookieName,
			CookieDomain:   cfg.CSRF.CookieDomain,
			CookiePath:     cfg.CSRF.CookiePath,
			CookieMaxAge:   cfg.CSRF.CookieMaxAge,
			CookieSecure:   cfg.CSRF.CookieSecure,
			CookieHTTPOnly: cfg.CSRF.CookieHTTPOnly,
			CookieSameSite: http.SameSite(cfg.CSRF.CookieSameSite),
		}))
	}

	if cfg.Compress.Enabled {
		middlewares = append(middlewares, middleware.GzipWithConfig(middleware.GzipConfig{
			Level:     cfg.Compress.Level,
			MinLength: cfg.Compress.MinLength,
		}))
	}

	if cfg.Healthcheck.Enabled {
		healthcheck.New(e, healthcheck.Config{
			LivenessEndpoint:  cfg.Healthcheck.LivenessEndpoint,
			ReadinessEndpoint: cfg.Healthcheck.ReadinessEndpoint,
			StartupEndpoint:   cfg.Healthcheck.StartupEndpoint,
		})
	}

	if cfg.Prometheus.Enabled {
		middlewares = append(middlewares, echoprometheus.NewMiddlewareWithConfig(echoprometheus.MiddlewareConfig{
			Namespace: "",
			Subsystem: cfg.Name,
		}))
		e.GET(srv.cfg.Prometheus.Path, echoprometheus.NewHandler())
	}

	if cfg.RateLimiter.Enabled {
		switch cfg.RateLimiter.Store {
		case LimiterStoreMemory:
			s := middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
				Rate:      rate.Limit(cfg.RateLimiter.Memory.Rate),
				Burst:     cfg.RateLimiter.Memory.Burst,
				ExpiresIn: cfg.RateLimiter.Memory.ExpiresIn,
			})

			middlewares = append(middlewares, middleware.RateLimiter(s))
		}
	}

	if cfg.Recover.Enabled {
		middlewares = append(middlewares, middleware.RecoverWithConfig(middleware.RecoverConfig{
			StackSize:           cfg.Recover.StackSize,
			DisableStackAll:     cfg.Recover.DisableStackAll,
			DisablePrintStack:   cfg.Recover.DisablePrintStack,
			DisableErrorHandler: cfg.Recover.DisableErrorHandler,
		}))
	}

	if cfg.RequestID.Enabled {
		middlewares = append(middlewares, middleware.RequestIDWithConfig(middleware.RequestIDConfig{
			TargetHeader: cfg.RequestID.TargetHeader,
		}))
	}

	if cfg.Secure.Enabled {
		middlewares = append(middlewares, secure.New(secure.Config{
			ContentSecurityPolicy:           cfg.Secure.ContentSecurityPolicy,
			ContentSecurityPolicyReportOnly: cfg.Secure.ContentSecurityPolicyReportOnly,
			CrossOriginEmbedderPolicy:       cfg.Secure.CrossOriginEmbedderPolicy,
			CrossOriginOpenerPolicy:         cfg.Secure.CrossOriginOpenerPolicy,
			CrossOriginResourcePolicy:       cfg.Secure.CrossOriginResourcePolicy,
			PermissionsPolicy:               cfg.Secure.PermissionsPolicy,
			ReferrerPolicy:                  cfg.Secure.ReferrerPolicy,
			Server:                          cfg.Secure.Server,
			StrictTransportSecurity: secure.StrictTransportSecurity{
				MaxAge:            cfg.Secure.StrictTransportSecurity.MaxAge,
				ExcludeSubdomains: cfg.Secure.StrictTransportSecurity.ExcludeSubdomains,
				PreloadEnabled:    cfg.Secure.StrictTransportSecurity.PreloadEnabled,
			},
			XContentTypeOptions: srv.cfg.Secure.XContentTypeOptions,
			XFrameOptions:       srv.cfg.Secure.XFrameOptions,
		}))
	}

	if cfg.Session.Enabled {
		switch cfg.Session.Store {
		case SessionStoreCookie:
			s := session.Middleware(sessions.NewCookieStore([]byte(cfg.Session.Cookie.Secret)))
			middlewares = append(middlewares, s)
		case SessionStoreRedis:
			opts, err := redis.ParseURL(cfg.Session.Redis.URI)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to parse redis uri")
			}

			client := redis.NewClient(opts)

			s, err := redisstore.NewRedisStore(context.Background(), client)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to initialize redis store")
			}

			middlewares = append(middlewares, session.Middleware(s))
		case SessionStoreRedisSentinel:
			client := redis.NewFailoverClient(&redis.FailoverOptions{
				MasterName:    cfg.Session.RedisSentinel.MasterName,
				SentinelAddrs: cfg.Session.RedisSentinel.SentinelAddrs,
			})

			s, err := redisstore.NewRedisStore(context.Background(), client)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to initialize redis-sentinel store")
			}

			middlewares = append(middlewares, session.Middleware(s))

		case SessionStoreRedisCluster:
			opts, err := redis.ParseClusterURL(cfg.Session.RedisCluster.URI)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to parse redis-cluster uri")
			}

			client := redis.NewClusterClient(opts)

			s, err := redisstore.NewRedisStore(context.Background(), client)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to initialize redis-cluster store")
			}

			middlewares = append(middlewares, session.Middleware(s))
		}
	}

	if cfg.Static.Enabled {
		middlewares = append(middlewares, middleware.StaticWithConfig(middleware.StaticConfig{
			Root:       cfg.Static.Root,
			Index:      cfg.Static.Index,
			HTML5:      cfg.Static.HTML5,
			Browse:     cfg.Static.Browse,
			IgnoreBase: cfg.Static.IgnoreBase,
		}))
	}

	if cfg.HTTP.LogRequests {
		middlewares = append(middlewares, middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
			HandleError:      true,
			LogRequestID:     true,
			LogRemoteIP:      true,
			LogHost:          true,
			LogMethod:        true,
			LogURI:           true,
			LogUserAgent:     true,
			LogStatus:        true,
			LogError:         true,
			LogLatency:       true,
			LogContentLength: true,
			LogResponseSize:  true,
			LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
				i, _ := strconv.Atoi(v.ContentLength)
				log.Logger.Info().
					Str("time", time.Now().Format(time.RFC3339Nano)).
					Str("id", v.RequestID).
					Str("remote_id", v.RemoteIP).
					Str("host", v.Host).
					Str("method", v.Method).
					Str("uri", v.URI).
					Str("user_agent", v.UserAgent).
					Int("status", v.Status).
					Err(v.Error).
					Int64("latency", v.Latency.Nanoseconds()).
					Str("latency_human", v.Latency.String()).
					Int64("bytes_in", int64(i)).
					Int64("bytes_out", v.ResponseSize).
					Send()

				return nil
			},
		}))
	}

	e.Use(middlewares...)

	humaCfg := huma.DefaultConfig(cfg.Name, app.Version)
	humaCfg.CreateHooks = nil

	api := humaecho.New(e, humaCfg)
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		echoCtx := humaecho.Unwrap(ctx)
		req := echoCtx.Request()
		newCtx := context.WithValue(req.Context(), echoCtxKey{}, echoCtx)
		echoCtx.SetRequest(req.WithContext(newCtx))
		next(ctx)
	})

	huma.Register(api, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Hello",
		Description: "Returns hello message",
	}, srv.Hello)

	return srv, nil
}

func (s *Service) Start() <-chan error {
	s.httpServer = s.createServer(s.cfg.HTTP.BindAddr, s.e)

	if !s.cfg.TLS.Enabled {
		go func() {
			if err := s.httpServer.ListenAndServe(); err != nil {
				s.errCh <- fmt.Errorf("HTTP server error: %w", err)
			}
		}()
	} else {
		acmeClient := &acme.Client{}
		autocertManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Email:      s.cfg.TLS.ACME.Email,
			HostPolicy: autocert.HostWhitelist(s.cfg.TLS.ACME.HostWhitelist...),
			Cache:      autocert.DirCache(s.cfg.TLS.ACME.CachePath),
		}

		if s.cfg.TLS.ACME.DirectoryURL != "" {
			acmeClient.DirectoryURL = s.cfg.TLS.ACME.DirectoryURL
		}

		autocertManager.Client = acmeClient

		tlsConfig := &tls.Config{
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: defaultCurves,
			CipherSuites:     getOptimalDefaultCipherSuites(),
		}

		s.httpsServer = s.createServer(s.cfg.TLS.BindAddr, s.e)
		s.httpsServer.TLSConfig = tlsConfig

		// HTTP server that listens on port 80 for challenges
		if s.cfg.TLS.ACME.Enabled {
			_, port, err := net.SplitHostPort(s.cfg.HTTP.BindAddr)
			if err != nil {
				s.errCh <- fmt.Errorf("failed to split host/port: %w", err)
				return s.errCh
			}

			if port != "80" {
				s.errCh <- fmt.Errorf("bind-addr must be set to port 80 for the challenge server")
				return s.errCh
			}

			s.httpServer.Handler = autocertManager.HTTPHandler(nil)
			go func() {
				if err := s.httpServer.ListenAndServe(); err != nil {
					s.errCh <- fmt.Errorf("HTTP server error: %w", err)
				}
			}()
		}

		if !s.cfg.TLS.ACME.Enabled {
			go func() {
				if err := s.httpsServer.ListenAndServeTLS(
					s.cfg.TLS.CertFile,
					s.cfg.TLS.KeyFile,
				); err != nil {
					s.errCh <- fmt.Errorf("HTTPS server error: %w", err)
				}
			}()
		} else {
			_, port, err := net.SplitHostPort(s.cfg.TLS.BindAddr)
			if err != nil {
				s.errCh <- fmt.Errorf("failed to split host/port: %w", err)
				return s.errCh
			}

			if port != "443" {
				s.errCh <- fmt.Errorf("tls-bind-addr must be set to port 443 for auto TLS")
				return s.errCh
			}

			tlsConfig.GetCertificate = autocertManager.GetCertificate
			go func() {
				if err := s.httpsServer.ListenAndServeTLS("", ""); err != nil {
					s.errCh <- fmt.Errorf("HTTPS server error: %w", err)
				}
			}()
		}

		if s.cfg.Redirect.HTTPS && !s.cfg.TLS.ACME.Enabled {
			s.e.Pre(s.redirect)
			if s.httpServer.Handler == nil || s.httpServer.Handler == s.e {
				go func() {
					if err := s.httpServer.ListenAndServe(); err != nil {
						s.errCh <- fmt.Errorf("HTTP server error: %w", err)
					}
				}()
			}
		}
	}

	return s.errCh
}

func (s *Service) Shutdown(ctx context.Context) error {
	// signal all goroutines to stop
	s.cancel()

	var errs []error

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("HTTP server shutdown error: %w", err))
		}
	}

	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("HTTPS server shutdown error: %w", err))
		}
	}

	close(s.errCh)

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (s *Service) createServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		IdleTimeout:       s.cfg.HTTP.IdleTimeout,
		ReadTimeout:       s.cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: s.cfg.HTTP.ReadHeaderTimeout,
		WriteTimeout:      s.cfg.HTTP.WriteTimeout,
	}
}

func (s *Service) redirect(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		req, scheme := c.Request(), c.Scheme()
		if scheme != "https" {
			host := req.Host

			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}

			_, tlsPort, err := net.SplitHostPort(s.cfg.TLS.BindAddr)
			if err != nil {
				return err
			}

			// if TLS port is the default (443), don't include it in the URL
			portSuffix := ""
			if tlsPort != "443" {
				portSuffix = ":" + tlsPort
			}

			url := fmt.Sprintf("https://%s%s%s", host, portSuffix, req.RequestURI)
			return c.Redirect(s.cfg.Redirect.Code, url)
		}

		return next(c)
	}
}
