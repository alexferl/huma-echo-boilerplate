package service

import (
	"net/http"
	"testing"
)

func TestCSRFSameSiteMode_String(t *testing.T) {
	tests := []struct {
		name string
		mode CSRFSameSiteMode
		want string
	}{
		{
			name: "Default mode",
			mode: CSRFSameSiteDefaultMode,
			want: csrfSameSiteDefaultMode,
		},
		{
			name: "Lax mode",
			mode: CSRFSameSiteLaxMode,
			want: csrfSameSiteLaxMode,
		},
		{
			name: "Strict mode",
			mode: CSRFSameSiteStrictMode,
			want: csrfSameSiteStrictMode,
		},
		{
			name: "None mode",
			mode: CSRFSameSiteNoneMode,
			want: csrfSameSiteNoneMode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.mode
			if got := m.String(); got != tt.want {
				t.Errorf("CSRFSameSiteMode.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCSRFSameSiteMode_Set(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    CSRFSameSiteMode
		wantErr bool
	}{
		{
			name:    "Default mode",
			value:   csrfSameSiteDefaultMode,
			want:    CSRFSameSiteMode(http.SameSiteDefaultMode),
			wantErr: false,
		},
		{
			name:    "Lax mode",
			value:   csrfSameSiteLaxMode,
			want:    CSRFSameSiteMode(http.SameSiteLaxMode),
			wantErr: false,
		},
		{
			name:    "Strict mode",
			value:   csrfSameSiteStrictMode,
			want:    CSRFSameSiteMode(http.SameSiteStrictMode),
			wantErr: false,
		},
		{
			name:    "None mode",
			value:   csrfSameSiteNoneMode,
			want:    CSRFSameSiteMode(http.SameSiteNoneMode),
			wantErr: false,
		},
		{
			name:    "Upper case",
			value:   "LAX",
			want:    CSRFSameSiteMode(http.SameSiteLaxMode),
			wantErr: false,
		},
		{
			name:    "Invalid mode",
			value:   "invalid",
			want:    CSRFSameSiteMode(0), // Unchanged
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m CSRFSameSiteMode
			err := m.Set(tt.value)

			if (err != nil) != tt.wantErr {
				t.Errorf("CSRFSameSiteMode.Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && m != tt.want {
				t.Errorf("CSRFSameSiteMode.Set() = %v, want %v", m, tt.want)
			}
		})
	}
}

func TestCSRFSameSiteMode_Type(t *testing.T) {
	var m CSRFSameSiteMode
	if got := m.Type(); got != "string" {
		t.Errorf("CSRFSameSiteMode.Type() = %v, want %v", got, "string")
	}
}

func TestCSRFSameSiteMode_String_Undefined(t *testing.T) {
	m := CSRFSameSiteMode(999) // Some undefined value
	result := m.String()
	if result == "" {
		t.Errorf("CSRFSameSiteMode.String() for unknown mode returned empty string")
	}
}
