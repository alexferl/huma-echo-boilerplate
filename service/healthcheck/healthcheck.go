package healthcheck

import (
	"github.com/labstack/echo/v4"
)

// New creates and registers all healthcheck endpoints with default handlers
func New(app *echo.Echo, config ...Config) {
	cfg := defaultConfig(config...)

	app.GET(cfg.LivenessEndpoint, cfg.LivenessHandler)
	app.GET(cfg.ReadinessEndpoint, cfg.ReadinessHandler)
	app.GET(cfg.StartupEndpoint, cfg.StartupHandler)
}
