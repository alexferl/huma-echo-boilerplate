package config

import (
	"fmt"
	"strings"
	"time"
)

type RateLimiterMemoryStore struct {
	Rate      float64
	Burst     int
	ExpiresIn time.Duration
}

type RateLimiterStore string

const (
	limiterStoreMemory = "memory"
)

const (
	LimiterStoreMemory RateLimiterStore = limiterStoreMemory
)

var limiterStores = []string{limiterStoreMemory}

func (s *RateLimiterStore) String() string {
	switch *s {
	case LimiterStoreMemory:
		return limiterStoreMemory
	default:
		return fmt.Sprintf("unknown store: %s", *s)
	}
}

func (s *RateLimiterStore) Set(value string) error {
	switch strings.ToLower(value) {
	case limiterStoreMemory:
		*s = LimiterStoreMemory
		return nil
	default:
		return fmt.Errorf("invalid rate limiter store: %s (must be one of: %s)", value, strings.Join(limiterStores, ", "))
	}
}

func (s *RateLimiterStore) Type() string {
	return "string"
}
