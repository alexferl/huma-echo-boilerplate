package config

import (
	"fmt"
	"net/http"
	"strings"
)

type CSRFSameSiteMode http.SameSite

const (
	csrfSameSiteDefaultMode = "default"
	csrfSameSiteLaxMode     = "lax"
	csrfSameSiteStrictMode  = "strict"
	csrfSameSiteNoneMode    = "none"
)

const (
	CSRFSameSiteDefaultMode CSRFSameSiteMode = iota + 1
	CSRFSameSiteLaxMode
	CSRFSameSiteStrictMode
	CSRFSameSiteNoneMode
)

var csrfSameSiteModes = []string{csrfSameSiteDefaultMode, csrfSameSiteLaxMode, csrfSameSiteStrictMode, csrfSameSiteNoneMode}

func (m *CSRFSameSiteMode) String() string {
	switch *m {
	case CSRFSameSiteDefaultMode:
		return csrfSameSiteDefaultMode
	case CSRFSameSiteLaxMode:
		return csrfSameSiteLaxMode
	case CSRFSameSiteStrictMode:
		return csrfSameSiteStrictMode
	case CSRFSameSiteNoneMode:
		return csrfSameSiteNoneMode
	default:
		return fmt.Sprintf("unknown mode: %d", *m)
	}
}

func (m *CSRFSameSiteMode) Set(value string) error {
	switch strings.ToLower(value) {
	case csrfSameSiteDefaultMode:
		*m = CSRFSameSiteMode(http.SameSiteDefaultMode)
		return nil
	case csrfSameSiteLaxMode:
		*m = CSRFSameSiteMode(http.SameSiteLaxMode)
		return nil
	case csrfSameSiteStrictMode:
		*m = CSRFSameSiteMode(http.SameSiteStrictMode)
		return nil
	case csrfSameSiteNoneMode:
		*m = CSRFSameSiteMode(http.SameSiteNoneMode)
		return nil
	default:
		return fmt.Errorf("invalid same site mode: %s (must be one of: %s)", value, strings.Join(csrfSameSiteModes, ", "))
	}
}

func (m *CSRFSameSiteMode) Type() string {
	return "string"
}
