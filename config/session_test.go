package config

import (
	"testing"
)

func TestSessionStore_String(t *testing.T) {
	tests := []struct {
		name  string
		store SessionStore
		want  string
	}{
		{
			name:  "Cookie store",
			store: SessionStoreCookie,
			want:  "cookie",
		},
		{
			name:  "Redis store",
			store: SessionStoreRedis,
			want:  "redis",
		},
		{
			name:  "Redis cluster store",
			store: SessionStoreRedisCluster,
			want:  "redis-cluster",
		},
		{
			name:  "Redis sentinel store",
			store: SessionStoreRedisSentinel,
			want:  "redis-sentinel",
		},
		{
			name:  "Unknown store",
			store: SessionStore("unknown"),
			want:  "unknown store: unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.store.String(); got != tt.want {
				t.Errorf("SessionStore.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionStore_Set(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    SessionStore
		wantErr bool
	}{
		{
			name:    "Set cookie store",
			value:   "cookie",
			want:    SessionStoreCookie,
			wantErr: false,
		},
		{
			name:    "Set redis store",
			value:   "redis",
			want:    SessionStoreRedis,
			wantErr: false,
		},
		{
			name:    "Set redis cluster store",
			value:   "redis-cluster",
			want:    SessionStoreRedisCluster,
			wantErr: false,
		},
		{
			name:    "Set redis sentinel store",
			value:   "redis-sentinel",
			want:    SessionStoreRedisSentinel,
			wantErr: false,
		},
		{
			name:    "Set with uppercase",
			value:   "COOKIE",
			want:    SessionStoreCookie,
			wantErr: false,
		},
		{
			name:    "Set with mixed case",
			value:   "ReDiS",
			want:    SessionStoreRedis,
			wantErr: false,
		},
		{
			name:    "Set invalid store",
			value:   "invalid",
			want:    SessionStore(""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s SessionStore
			err := s.Set(tt.value)

			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStore.Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && s != tt.want {
				t.Errorf("SessionStore.Set() = %v, want %v", s, tt.want)
			}
		})
	}
}

func TestSessionStore_Type(t *testing.T) {
	var s SessionStore
	if got := s.Type(); got != "string" {
		t.Errorf("SessionStore.Type() = %v, want %v", got, "string")
	}
}

func TestSessionStoreStructs(t *testing.T) {
	// Test SessionCookieStore
	cookieStore := SessionCookieStore{Secret: "test-secret"}
	if cookieStore.Secret != "test-secret" {
		t.Errorf("SessionCookieStore.Secret = %v, want %v", cookieStore.Secret, "test-secret")
	}

	// Test SessionRedisStore
	redisStore := SessionRedisStore{URI: "redis://localhost:6379"}
	if redisStore.URI != "redis://localhost:6379" {
		t.Errorf("SessionRedisStore.URI = %v, want %v", redisStore.URI, "redis://localhost:6379")
	}

	// Test SessionRedisClusterStore
	redisClusterStore := SessionRedisClusterStore{URI: "redis://localhost:6379,redis://localhost:6380"}
	if redisClusterStore.URI != "redis://localhost:6379,redis://localhost:6380" {
		t.Errorf("SessionRedisClusterStore.URI = %v, want %v", redisClusterStore.URI, "redis://localhost:6379,redis://localhost:6380")
	}

	// Test SessionRedisSentinelStore
	redisSentinelStore := SessionRedisSentinelStore{
		MasterName:    "mymaster",
		SentinelAddrs: []string{"localhost:26379", "localhost:26380"},
	}
	if redisSentinelStore.MasterName != "mymaster" {
		t.Errorf("SessionRedisSentinelStore.MasterName = %v, want %v", redisSentinelStore.MasterName, "mymaster")
	}
	if len(redisSentinelStore.SentinelAddrs) != 2 {
		t.Errorf("len(SessionRedisSentinelStore.SentinelAddrs) = %v, want %v", len(redisSentinelStore.SentinelAddrs), 2)
	}
	if redisSentinelStore.SentinelAddrs[0] != "localhost:26379" {
		t.Errorf("SessionRedisSentinelStore.SentinelAddrs[0] = %v, want %v", redisSentinelStore.SentinelAddrs[0], "localhost:26379")
	}
	if redisSentinelStore.SentinelAddrs[1] != "localhost:26380" {
		t.Errorf("SessionRedisSentinelStore.SentinelAddrs[1] = %v, want %v", redisSentinelStore.SentinelAddrs[1], "localhost:26380")
	}
}
