package service

import (
	"testing"
	"time"
)

func TestRateLimiterStore_String(t *testing.T) {
	tests := []struct {
		name  string
		store RateLimiterStore
		want  string
	}{
		{
			name:  "Memory store",
			store: LimiterStoreMemory,
			want:  limiterStoreMemory,
		},
		{
			name:  "Unknown store",
			store: RateLimiterStore("unknown"),
			want:  "unknown store: unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.store.String(); got != tt.want {
				t.Errorf("RateLimiterStore.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRateLimiterStore_Set(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    RateLimiterStore
		wantErr bool
	}{
		{
			name:    "Valid memory store",
			value:   "memory",
			want:    LimiterStoreMemory,
			wantErr: false,
		},
		{
			name:    "Valid memory store (uppercase)",
			value:   "MEMORY",
			want:    LimiterStoreMemory,
			wantErr: false,
		},
		{
			name:    "Invalid store",
			value:   "invalid",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s RateLimiterStore
			err := s.Set(tt.value)

			if (err != nil) != tt.wantErr {
				t.Errorf("RateLimiterStore.Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && s != tt.want {
				t.Errorf("RateLimiterStore.Set() = %v, want %v", s, tt.want)
			}
		})
	}
}

func TestRateLimiterStore_Type(t *testing.T) {
	var s RateLimiterStore
	if got := s.Type(); got != "string" {
		t.Errorf("RateLimiterStore.Type() = %v, want %v", got, "string")
	}
}

func TestRateLimiterMemory(t *testing.T) {
	rlm := RateLimiterMemoryStore{
		Rate:      10.0,
		Burst:     20,
		ExpiresIn: 5 * time.Minute,
	}

	if rlm.Rate != 10.0 {
		t.Errorf("RateLimiterMemoryStore.Rate = %v, want %v", rlm.Rate, 10.0)
	}

	if rlm.Burst != 20 {
		t.Errorf("RateLimiterMemoryStore.Burst = %v, want %v", rlm.Burst, 20)
	}

	if rlm.ExpiresIn != 5*time.Minute {
		t.Errorf("RateLimiterMemoryStore.ExpiresIn = %v, want %v", rlm.ExpiresIn, 5*time.Minute)
	}
}
