package healthcheck

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func defaultHandler(c echo.Context) error {
	return c.String(http.StatusOK, "ok")
}

// Config allows customizing the healthcheck endpoints
type Config struct {
	LivenessEndpoint  string
	LivenessHandler   echo.HandlerFunc
	ReadinessEndpoint string
	ReadinessHandler  echo.HandlerFunc
	StartupEndpoint   string
	StartupHandler    echo.HandlerFunc
}

var DefaultConfig = Config{
	LivenessEndpoint:  "/livez",
	LivenessHandler:   defaultHandler,
	ReadinessEndpoint: "/readyz",
	ReadinessHandler:  defaultHandler,
	StartupEndpoint:   "/startupz",
	StartupHandler:    defaultHandler,
}

func defaultConfig(config ...Config) Config {
	if len(config) < 1 {
		return DefaultConfig
	}

	cfg := config[0]

	if cfg.LivenessEndpoint == "" {
		cfg.LivenessEndpoint = DefaultConfig.LivenessEndpoint
	}

	if cfg.LivenessHandler == nil {
		cfg.LivenessHandler = DefaultConfig.LivenessHandler
	}

	if cfg.ReadinessEndpoint == "" {
		cfg.ReadinessEndpoint = DefaultConfig.ReadinessEndpoint
	}

	if cfg.ReadinessHandler == nil {
		cfg.ReadinessHandler = DefaultConfig.ReadinessHandler
	}

	if cfg.StartupEndpoint == "" {
		cfg.StartupEndpoint = DefaultConfig.StartupEndpoint
	}

	if cfg.StartupHandler == nil {
		cfg.StartupHandler = DefaultConfig.StartupHandler
	}

	return cfg
}
