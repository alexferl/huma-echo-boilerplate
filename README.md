# huma-echo-boilerplate [![Go Report Card](https://goreportcard.com/badge/github.com/alexferl/huma-echo-boilerplate)](https://goreportcard.com/report/github.com/alexferl/huma-echo-boilerplate) [![codecov](https://codecov.io/gh/alexferl/huma-echo-boilerplate/branch/master/graph/badge.svg)](https://codecov.io/gh/alexferl/huma-echo-boilerplate)
A [Huma](https://huma.rocks/) + [Echo](https://echo.labstack.com/) Go boilerplate.

## Requirements
- Go 1.23+

## Using
```shell
git clone https://github.com/alexferl/huma-echo-boilerplate.git myapp
cd myapp
make dev
```

See which other commands are available with:
```shell
make help
```

Config:
```
Usage: app [flags]

Server configuration options:
  --app-name           Application name (default app)
  --env-name           Environment name (default local)
  --config-prefix      Sets the prefix for configuration files to be loaded, e.g., "config" would match "config.{env_name}.toml" (default config)
  --config-type        Defines the format of configuration files to be loaded (default toml)
                       Values: json, toml, or yaml
  --config-paths       Specifies directories where configuration files will be searched for, in order of preference (default [./configs,/configs])
  --bind-addr          Server binding address (default 127.0.0.1:1323)
  --graceful-timeout   Sets the maximum time to wait for in-flight requests to complete before shutting down the server (default 30s)
  --log-requests       Enables or disables logging of incoming HTTP requests (default true)

Body limit middleware configuration options:
  --body-limit   Sets the maximum allowed size of the request body, use values like "100K", "10M" or "1G"

CORS middleware configuration options:
  --cors-enabled             Enable CORS middleware (default false)
  --cors-allow-origins       Allowed origins for CORS requests (default [*])
  --cors-allow-methods       Allowed HTTP methods in CORS request (default [GET,HEAD,PUT,PATCH,POST,DELETE])
  --cors-allow-headers       Allowed headers in CORS requests (default [])
  --cors-allow-credentials   Allow credentials in CORS requests (default false)
  --cors-expose-headers      Headers exposed to browsers in CORS responses (default [])
  --cors-max-age             Max age (in seconds) for CORS preflight responses (default 0)

CSRF middleware configuration options:
  --csrf-enabled            Enable CSRF protection middleware (default false)
  --csrf-token-length       Length of generated CSRF token in bytes (default 32)
  --csrf-token-lookup       Location to extract CSRF token from request (default header:X-CSRF-Token)
  --csrf-context-key        Key used to store CSRF token in context (default csrf)
  --csrf-cookie-name        Name of the CSRF cookie (default _csrf)
  --csrf-cookie-domain      Domain attribute for CSRF cookie
  --csrf-cookie-path        Path attribute for CSRF cookie
  --csrf-cookie-max-age     Maximum age in seconds for CSRF cookie  (default 86400)
  --csrf-cookie-secure      Set Secure flag on CSRF cookie (default false)
  --csrf-cookie-http-only   Set HttpOnly flag on CSRF cookie (default false)
  --csrf-cookie-same-site   SameSite attribute for CSRF cookie (default default)
                            Values: default, lax, strict, node

GZIP middleware configuration options:
  --gzip-enabled      Enable GZIP compression (default false)
  --gzip-level        Compression level (default -1)
  --gzip-min-length   Minimum response size in bytes before compression is applied (default 0)

Healthcheck endpoints configuration options:
  --healthcheck-enabled              Enable health check endpoints (default true)
  --healthcheck-liveness-endpoint    Path for the liveness health check endpoint that indicates if the application is running
  --healthcheck-readiness-endpoint   Path for the readiness health check endpoint that indicates if the application is ready to receive traffic
  --healthcheck-startup-endpoint     Path for the startup health check endpoint that indicates if the application has completed its initialization

Logging configuration options:
  --log-level    Log granularity (default INFO)
                 Values: PANIC, FATAL, ERROR, WARN, INFO, DISABLED, TRACE, DISABLED
  --log-output   Output destination (default stdout)
                 Values: stdout, stderr
  --log-writer   Log format (default text)
                 Values: text, json

Prometheus configuration options:
  --prometheus-enabled   Enables Prometheus metrics collection and exposure for application monitoring (default false)
  --prometheus-path      Sets the HTTP path where Prometheus metrics will be exposed (default /metrics)

Rate limiter middleware configuration options:
  --ratelimiter-enabled             Enable rate limiting middleware (default false)
  --ratelimiter-store               Storage backend for rate limiting (default memory)
                                    Values: memory
  --ratelimiter-memory-rate         Maximum request rate per time window (default 0)
  --ratelimiter-memory-burst        Maximum number of requests allowed to exceed the rate (default 0)
  --ratelimiter-memory-expires-in   Time window for rate limit expiration (default 3m0s)

Recover middleware configuration options:
  --recover-enabled                 Enable automatic recovery from panics (default true)
  --recover-stack-size              recover (default 4096)
  --recover-disable-stack-all       Disables capturing the complete stack trace during panic recovery (default false)
  --recover-disable-print-stack     Prevents printing the stack trace when recovering from panics (default false)
  --recover-disable-error-handler   Disables the default error handler for panics, allowing the application to crash instead of recovering (default false)

Request ID middleware configuration options:
  --requestid-enabled         Enable request ID middleware (default true)
  --requestid-target-header   Custom header for request ID (default X-Request-Id)

Security headers configuration options:
  --secure-enabled                               Enables all security headers for enhanced protection against common web vulnerabilities (default false)
  --secure-content-security-policy               Sets the Content-Security-Policy header to help prevent cross-site scripting and other code injection attacks
  --secure-content-security-policy-report-only   Enables report-only mode for CSP, which reports violations but doesn't enforce the policy (default false)
  --secure-content-type-no-sniff                 Sets the X-Content-Type-Options header to prevent MIME type sniffing (default nosniff)
  --secure-hsts-exclude-subdomains               Excludes subdomains from the HSTS policy, limiting it to the main domain only (default false)
  --secure-hsts-max-age                          Sets the max age in seconds for the Strict-Transport-Security header (default 0)
  --secure-hsts-preload-enabled                  Adds the preload directive to the HSTS header, allowing the site to be included in browser preload lists (default false)
  --secure-referrer-policy                       Sets the Referrer-Policy header to control how much referrer information is included with requests
  --secure-x-frame-options                       Sets the X-Frame-Options header to prevent clickjacking attacks (default SAMEORIGIN)
  --secure-xss-protection                        Sets the X-XSS-Protection header to enable browser's built-in XSS filtering (default 1; mode=block)

Session middleware configuration options:
  --session-enabled                      Enables session management for maintaining user state across requests (default false)
  --session-store                        Specifies the storage backend for session data (default cookie)
                                         Values: cookie, redis, redis-cluster, redis-sentinel
  --session-cookie-secret                Sets the secret key used to sign and encrypt session cookies, this should be a strong, random value in production (default changeme)
  --session-redis-uri                    Specifies the URI for connecting to a standalone Redis server for session storage (default redis://localhost:6379)
                                         Format: redis://[user:password@]host[:port][/database]
  --session-redis-cluster-uri            Specifies the URI for connecting to a Redis Cluster deployment for session storage, multiple nodes can be separated by commas (default redis://localhost:6379)
  --session-redis-sentinel-master-name   Specifies the name of the master node in a Redis Sentinel configuration (default mymaster)
  --session-redis-sentinel-addrs         Lists the addresses of Redis Sentinel nodes for high availability session storage (default [localhost:6379])

Static file serving configuration options:
  --static-enabled       Enables serving of static files from the specified directory (default false)
  --static-root          Specifies the root directory from which to serve static files
  --static-index         Sets the default file to serve when a directory is requested (default index.html)
  --static-html5         Enables HTML5 mode which redirects all not-found requests to index.html for single-page applications (default false)
  --static-browse        Enables directory browsing when no index file is present (default false)
  --static-ignore-base   Ignores the base path when serving static files, useful when your app is mounted under a sub-path (default false)

Timeout middleware configuration options:
  --timeout-enabled         Enable request timeout middleware (default true)
  --timeout-error-message   Custom error message when request times out
  --timeout-time            Maximum duration allowed for request processing (default 0s)
```
