package config

import (
	"fmt"
	"strings"
)

type SessionCookieStore struct {
	Secret string
}

type SessionRedisStore struct {
	URI string
}

type SessionRedisClusterStore struct {
	URI string
}

type SessionRedisSentinelStore struct {
	MasterName    string
	SentinelAddrs []string
}

type SessionStore string

const (
	sessionStoreCookie        = "cookie"
	sessionStoreRedis         = "redis"
	sessionStoreRedisCluster  = "redis-cluster"
	sessionStoreRedisSentinel = "redis-sentinel"
)

const (
	SessionStoreCookie        SessionStore = sessionStoreCookie
	SessionStoreRedis         SessionStore = sessionStoreRedis
	SessionStoreRedisCluster  SessionStore = sessionStoreRedisCluster
	SessionStoreRedisSentinel SessionStore = sessionStoreRedisSentinel
)

var sessionStores = []string{sessionStoreCookie, sessionStoreRedis, sessionStoreRedisCluster, sessionStoreRedisSentinel}

func (s *SessionStore) String() string {
	switch *s {
	case SessionStoreCookie:
		return sessionStoreCookie
	case SessionStoreRedis:
		return sessionStoreRedis
	case SessionStoreRedisCluster:
		return sessionStoreRedisCluster
	case SessionStoreRedisSentinel:
		return sessionStoreRedisSentinel
	default:
		return fmt.Sprintf("unknown store: %s", *s)
	}
}

func (s *SessionStore) Set(value string) error {
	switch strings.ToLower(value) {
	case sessionStoreCookie:
		*s = SessionStoreCookie
		return nil
	case sessionStoreRedis:
		*s = SessionStoreRedis
		return nil
	case sessionStoreRedisCluster:
		*s = SessionStoreRedisCluster
		return nil
	case sessionStoreRedisSentinel:
		*s = SessionStoreRedisSentinel
		return nil
	default:
		return fmt.Errorf("invalid session store: %s (must be one of: %s)", value, strings.Join(sessionStores, ", "))
	}
}

func (s *SessionStore) Type() string {
	return "string"
}
