package healthcheck

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	// Setup
	e := echo.New()
	New(e)

	// Test liveness endpoint
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())

	// Test readiness endpoint
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())

	// Test startup endpoint
	req = httptest.NewRequest(http.MethodGet, "/startupz", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}

func TestNewWithCustomConfig(t *testing.T) {
	// Setup
	e := echo.New()
	customConfig := Config{
		LivenessEndpoint: "/custom-livez",
		LivenessHandler: func(c echo.Context) error {
			return c.String(http.StatusOK, "custom live")
		},
		ReadinessEndpoint: "/custom-readyz",
		ReadinessHandler: func(c echo.Context) error {
			return c.String(http.StatusOK, "custom ready")
		},
		StartupEndpoint: "/custom-startupz",
		StartupHandler: func(c echo.Context) error {
			return c.String(http.StatusOK, "custom startup")
		},
	}
	New(e, customConfig)

	// Test custom liveness endpoint
	req := httptest.NewRequest(http.MethodGet, "/custom-livez", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "custom live", rec.Body.String())

	// Test custom readiness endpoint
	req = httptest.NewRequest(http.MethodGet, "/custom-readyz", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "custom ready", rec.Body.String())

	// Test custom startup endpoint
	req = httptest.NewRequest(http.MethodGet, "/custom-startupz", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "custom startup", rec.Body.String())
}

func TestNewWithPartialConfig(t *testing.T) {
	// Setup
	e := echo.New()
	partialConfig := Config{
		LivenessEndpoint: "/custom-livez",
		// Other fields use defaults
	}
	New(e, partialConfig)

	// Test custom liveness endpoint
	req := httptest.NewRequest(http.MethodGet, "/custom-livez", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())

	// Test default readiness endpoint
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}
