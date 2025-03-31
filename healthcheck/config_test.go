package healthcheck

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestDefaultHandler(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := defaultHandler(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}

func TestDefaultConfig(t *testing.T) {
	tests := []struct {
		name     string
		input    []Config
		expected Config
	}{
		{
			name:     "No config provided",
			input:    []Config{},
			expected: DefaultConfig,
		},
		{
			name: "Custom config with all fields set",
			input: []Config{{
				LivenessEndpoint:  "/custom-live",
				LivenessHandler:   func(c echo.Context) error { return c.String(http.StatusOK, "custom live") },
				ReadinessEndpoint: "/custom-ready",
				ReadinessHandler:  func(c echo.Context) error { return c.String(http.StatusOK, "custom ready") },
				StartupEndpoint:   "/custom-startup",
				StartupHandler:    func(c echo.Context) error { return c.String(http.StatusOK, "custom startup") },
			}},
			expected: Config{
				LivenessEndpoint:  "/custom-live",
				LivenessHandler:   func(c echo.Context) error { return c.String(http.StatusOK, "custom live") },
				ReadinessEndpoint: "/custom-ready",
				ReadinessHandler:  func(c echo.Context) error { return c.String(http.StatusOK, "custom ready") },
				StartupEndpoint:   "/custom-startup",
				StartupHandler:    func(c echo.Context) error { return c.String(http.StatusOK, "custom startup") },
			},
		},
		{
			name: "Partial custom config",
			input: []Config{{
				LivenessEndpoint: "/custom-live",
				StartupEndpoint:  "/custom-startup",
			}},
			expected: Config{
				LivenessEndpoint:  "/custom-live",
				LivenessHandler:   defaultHandler,
				ReadinessEndpoint: "/readyz",
				ReadinessHandler:  defaultHandler,
				StartupEndpoint:   "/custom-startup",
				StartupHandler:    defaultHandler,
			},
		},
		{
			name: "Empty custom config",
			input: []Config{{
				LivenessEndpoint:  "",
				ReadinessEndpoint: "",
				StartupEndpoint:   "",
			}},
			expected: Config{
				LivenessEndpoint:  "/livez",
				LivenessHandler:   defaultHandler,
				ReadinessEndpoint: "/readyz",
				ReadinessHandler:  defaultHandler,
				StartupEndpoint:   "/startupz",
				StartupHandler:    defaultHandler,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := defaultConfig(tt.input...)
			assert.Equal(t, tt.expected.LivenessEndpoint, result.LivenessEndpoint)
			assert.Equal(t, tt.expected.ReadinessEndpoint, result.ReadinessEndpoint)
			assert.Equal(t, tt.expected.StartupEndpoint, result.StartupEndpoint)

			// Test handlers
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := result.LivenessHandler(c)
			assert.NoError(t, err)
			err = result.ReadinessHandler(c)
			assert.NoError(t, err)
			err = result.StartupHandler(c)
			assert.NoError(t, err)
		})
	}
}
