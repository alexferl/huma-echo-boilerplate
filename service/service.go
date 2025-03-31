package service

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

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
	"github.com/spf13/viper"
	"golang.org/x/time/rate"

	humafiberboilerplate "github.com/alexferl/huma-echo-boilerplate"
	"github.com/alexferl/huma-echo-boilerplate/config"
	"github.com/alexferl/huma-echo-boilerplate/healthcheck"
)

type Service struct {
	e *echo.Echo
}

func New() (*Service, error) {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	service := &Service{
		e: e,
	}

	var middlewares []echo.MiddlewareFunc
	if viper.GetString(config.BodyLimitLimit) != "" {
		middlewares = append(middlewares, middleware.BodyLimitWithConfig(middleware.BodyLimitConfig{
			Limit: viper.GetString(config.BodyLimitLimit),
		}))
	}

	if viper.GetBool(config.CORSEnabled) {
		middlewares = append(middlewares, middleware.CORSWithConfig(middleware.CORSConfig{
			AllowOrigins:     viper.GetStringSlice(config.CORSAllowOrigins),
			AllowMethods:     viper.GetStringSlice(config.CORSAllowMethods),
			AllowHeaders:     viper.GetStringSlice(config.CORSAllowHeaders),
			AllowCredentials: viper.GetBool(config.CORSAllowCredentials),
			ExposeHeaders:    viper.GetStringSlice(config.CORSExposeHeaders),
			MaxAge:           viper.GetInt(config.CORSMaxAge),
		}))
	}

	if viper.GetBool(config.CSRFEnabled) {
		middlewares = append(middlewares, middleware.CSRFWithConfig(middleware.CSRFConfig{
			TokenLength:    viper.GetUint8(config.CSRFTokenLength),
			TokenLookup:    viper.GetString(config.CSRFTokenLookup),
			ContextKey:     viper.GetString(config.CSRFContextKey),
			CookieName:     viper.GetString(config.CSRFCookieName),
			CookieDomain:   viper.GetString(config.CSRFCookieDomain),
			CookiePath:     viper.GetString(config.CSRFCookiePath),
			CookieMaxAge:   viper.GetInt(config.CSRFCookieMaxAge),
			CookieSecure:   viper.GetBool(config.CSRFCookieSecure),
			CookieHTTPOnly: viper.GetBool(config.CSRFCookieHTTPOnly),
			CookieSameSite: http.SameSite(viper.Get(config.CSRFCookieSameSite).(config.CSRFSameSiteMode)),
		}))
	}

	if viper.GetBool(config.GZIPEnabled) {
		middlewares = append(middlewares, middleware.GzipWithConfig(middleware.GzipConfig{
			Level:     viper.GetInt(config.GZIPLevel),
			MinLength: viper.GetInt(config.GZIPMinLength),
		}))
	}

	if viper.GetBool(config.HealthcheckEnabled) {
		healthcheck.New(e, healthcheck.Config{
			LivenessEndpoint:  viper.GetString(config.HealthcheckLivenessEndpoint),
			ReadinessEndpoint: viper.GetString(config.HealthcheckReadinessEndpoint),
			StartupEndpoint:   viper.GetString(config.HealthcheckStartupEndpoint),
		})
	}

	if viper.GetBool(config.PrometheusEnabled) {
		middlewares = append(middlewares, echoprometheus.NewMiddlewareWithConfig(echoprometheus.MiddlewareConfig{
			Namespace: "",
			Subsystem: viper.GetString(config.AppName),
		}))
		e.GET(viper.GetString(config.PrometheusPath), echoprometheus.NewHandler())
	}

	if viper.GetBool(config.RateLimiterEnabled) {
		switch viper.Get(config.RateLimiterStoreKind).(config.RateLimiterStore) {
		case config.LimiterStoreMemory:
			s := middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
				Rate:      rate.Limit(viper.GetFloat64(config.RateLimiterMemoryRate)),
				Burst:     viper.GetInt(config.RateLimiterMemoryBurst),
				ExpiresIn: viper.GetDuration(config.RateLimiterMemoryExpiresIn),
			})

			middlewares = append(middlewares, middleware.RateLimiter(s))
		}
	}

	if viper.GetBool(config.RecoverEnabled) {
		middlewares = append(middlewares, middleware.RecoverWithConfig(middleware.RecoverConfig{
			StackSize:           viper.GetInt(config.RecoverStackSize),
			DisableStackAll:     viper.GetBool(config.RecoverDisableStackAll),
			DisablePrintStack:   viper.GetBool(config.RecoverDisablePrintStack),
			DisableErrorHandler: viper.GetBool(config.RecoverDisableErrorHandler),
		}))
	}

	if viper.GetBool(config.RequestIDEnabled) {
		middlewares = append(middlewares, middleware.RequestIDWithConfig(middleware.RequestIDConfig{
			TargetHeader: viper.GetString(config.RequestIDTargetHeader),
		}))
	}

	if viper.GetBool(config.SecureEnabled) {
		middlewares = append(middlewares, middleware.SecureWithConfig(middleware.SecureConfig{
			XSSProtection:         viper.GetString(config.SecureXSSProtection),
			ContentTypeNosniff:    viper.GetString(config.SecureContentTypeNoSniff),
			XFrameOptions:         viper.GetString(config.SecureXFrameOptions),
			HSTSMaxAge:            viper.GetInt(config.SecureHSTSMaxAge),
			HSTSExcludeSubdomains: viper.GetBool(config.SecureHSTSExcludeSubdomains),
			ContentSecurityPolicy: viper.GetString(config.SecureContentSecurityPolicy),
			CSPReportOnly:         viper.GetBool(config.SecureContentSecurityPolicyReportOnly),
			HSTSPreloadEnabled:    viper.GetBool(config.SecureHSTSPreloadEnabled),
			ReferrerPolicy:        viper.GetString(config.SecureReferrerPolicy),
		}))
	}

	if viper.GetBool(config.SessionEnabled) {
		switch viper.Get(config.SessionStoreKind).(config.SessionStore) {
		case config.SessionStoreCookie:
			s := session.Middleware(sessions.NewCookieStore([]byte(viper.GetString(config.SessionCookieSecret))))
			middlewares = append(middlewares, s)
		case config.SessionStoreRedis:
			opts, err := redis.ParseURL(viper.GetString(config.SessionRedisURI))
			if err != nil {
				log.Fatal().Err(err).Msg("failed to parse redis uri")
			}

			client := redis.NewClient(opts)

			s, err := redisstore.NewRedisStore(context.Background(), client)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to initialize redis store")
			}

			middlewares = append(middlewares, session.Middleware(s))
		case config.SessionStoreRedisSentinel:
			client := redis.NewFailoverClient(&redis.FailoverOptions{
				MasterName:    viper.GetString(config.SessionRedisSentinelMasterName),
				SentinelAddrs: viper.GetStringSlice(config.SessionRedisSentinelAddrs),
			})

			s, err := redisstore.NewRedisStore(context.Background(), client)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to initialize redis-sentinel store")
			}

			middlewares = append(middlewares, session.Middleware(s))

		case config.SessionStoreRedisCluster:
			opts, err := redis.ParseClusterURL(viper.GetString(config.SessionRedisClusterURI))
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

	if viper.GetBool(config.StaticEnabled) {
		fmt.Printf("PD RACE %s\n", viper.GetString(config.StaticRoot))
		middlewares = append(middlewares, middleware.StaticWithConfig(middleware.StaticConfig{
			Root:       viper.GetString(config.StaticRoot),
			Index:      viper.GetString(config.StaticIndex),
			HTML5:      viper.GetBool(config.StaticHTML5),
			Browse:     viper.GetBool(config.StaticBrowse),
			IgnoreBase: viper.GetBool(config.StaticIgnoreBase),
		}))
	}

	if viper.GetBool(config.TimeoutEnabled) {
		middlewares = append(middlewares, middleware.TimeoutWithConfig(middleware.TimeoutConfig{
			ErrorMessage: viper.GetString(config.TimeoutErrorMessage),
			Timeout:      viper.GetDuration(config.TimeoutTime),
		}))
	}

	if viper.GetBool(config.LogRequests) {
		middlewares = append(middlewares, middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
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

	humaCfg := huma.DefaultConfig(viper.GetString(config.AppName), humafiberboilerplate.Version)
	humaCfg.CreateHooks = nil
	api := humaecho.New(e, humaCfg)

	huma.Register(api, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Hello",
		Description: "Returns hello message",
	}, service.Hello)

	return service, nil
}

func (s *Service) Start() <-chan error {
	errCh := make(chan error, 1)

	go func() {
		if err := s.e.Start(viper.GetString(config.BindAddr)); err != nil {
			errCh <- err
		}
	}()

	return errCh
}

func (s *Service) Shutdown(ctx context.Context) error {
	return s.e.Shutdown(ctx)
}
