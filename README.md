# huma-echo-boilerplate [![Go Report Card](https://goreportcard.com/badge/github.com/alexferl/huma-echo-boilerplate)](https://goreportcard.com/report/github.com/alexferl/huma-echo-boilerplate) [![codecov](https://codecov.io/gh/alexferl/huma-echo-boilerplate/branch/master/graph/badge.svg)](https://codecov.io/gh/alexferl/huma-echo-boilerplate)
A [Huma](https://huma.rocks/) + [Echo](https://echo.labstack.com/) Go boilerplate.

## Requirements
- Go 1.24+

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

## Config

These can be passed as CLI arguments, environment variables (`--app-name` -> `APP_NAME`) or in config files.

```
Usage: app [flags]

Server configuration options:
  --app-name string        Application name (default app)
  --env-name string        Environment name (default local)
  --config-type string     Defines the format of configuration files to be loaded (default toml)
                           Values: json, toml, or yaml
  --config-prefix string   Sets the prefix for configuration files to be loaded, e.g., "config" would match "config.{env_name}.{config_type}" (default config)
  --config-paths strings   Specifies directories where configuration files will be searched for, in order of preference (default [./configs,/configs])

Logging configuration options:
  --log-level string    Log granularity (default INFO)
                        Values: PANIC, FATAL, ERROR, WARN, INFO, DISABLED, TRACE, DISABLED
  --log-format string   Log format (default text)
                        Values: text, json
  --log-output string   Output destination (default stdout)
                        Values: stdout, stderr

HTTP server configuration options:
  --http-bind-addr string               Specifies the host:port address for the HTTP server to listen on (default localhost:8080)
  --http-graceful-timeout duration      Sets the maximum time to wait for in-flight requests to complete before shutting down the server (default 30s)
  --http-log-requests bool              Enables or disables logging of incoming HTTP requests (default true)
  --http-idle-timeout duration          Maximum duration to wait for the next request when keep-alives are enabled, a zero or negative value means there will be no timeout. (default 1m0s)
  --http-read-timeout duration          Maximum duration for reading the entire request, including the body, a zero or negative value means there will be no timeout (default 10s)
  --http-read-header-timeout duration   Maximum duration allowed for reading request headers, a zero or negative value means there will be no timeout (default 2s)
  --http-write-timeout duration         Maximum duration before timing out writes of the response, a zero or negative value means there will be no timeout (default 30s)
  --http-max-header-bytes int           Specifies the maximum number of bytes the server will read parsing the request header's keys and values, including the request line (default 2097152)

TLS configuration options:
  --tls-enabled bool                  Enables TLS encryption for secure communications, when enabled, the server requires HTTPS connections (default false)
  --tls-bind-addr string              Specifies the host:port address for the HTTPS server to listen on (default localhost:8443)
  --tls-cert-file string              Path to the TLS certificate file in PEM format containing the server's public key certificate
  --tls-key-file string               Path to the TLS private key file in PEM format corresponding to the certificate
  --tls-acme-enabled bool             Enables automatic TLS certificate provisioning using the ACME protocol (Let's Encrypt) (default false)
  --tls-acme-email string             Email address used for ACME account registration and certificate renewal notifications
  --tls-acme-cache-path string        Directory path where automatically provisioned TLS certificates will be stored (default ./certs)
  --tls-acme-host-whitelist strings   List of hostnames allowed for automatic certificate provisioning (default [])
  --tls-acme-directory-url string     URL of the ACME directory endpoint to use (default is Let's Encrypt production; use https://acme-staging-v02.api.letsencrypt.org/directory for testing)

Body limit middleware configuration options:
  --body-limit string   Sets the maximum allowed size of the request body, use values like "100K", "10M" or "1G" (default 1MB)

Compress middleware configuration options:
  --compress-enabled bool     Enable compression (default true)
  --compress-level int        Compression level (default 6)
  --compress-min-length int   Minimum response size in bytes before compression is applied (default 1400)

CORS middleware configuration options:
  --cors-enabled bool             Enable CORS middleware (default false)
  --cors-allow-origins strings    Allowed origins for CORS requests (default [*])
  --cors-allow-methods strings    Allowed HTTP methods in CORS request (default [GET,HEAD,PUT,PATCH,POST,DELETE])
  --cors-allow-headers strings    Allowed headers in CORS requests (default [])
  --cors-allow-credentials bool   Allow credentials in CORS requests (default false)
  --cors-expose-headers strings   Headers exposed to browsers in CORS responses (default [])
  --cors-max-age int              Max age (in seconds) for CORS preflight responses (default 0)

CSRF middleware configuration options:
  --csrf-enabled bool              Enable CSRF protection middleware (default false)
  --csrf-token-length uint8        Length of generated CSRF token in bytes (default 32)
  --csrf-token-lookup string       Location to extract CSRF token from request (default header:X-CSRF-Token)
  --csrf-context-key string        Key used to store CSRF token in context (default csrf)
  --csrf-cookie-name string        Name of the CSRF cookie (default _csrf)
  --csrf-cookie-domain string      Domain attribute for CSRF cookie
  --csrf-cookie-path string        Path attribute for CSRF cookie
  --csrf-cookie-max-age int        Maximum age in seconds for CSRF cookie  (default 86400)
  --csrf-cookie-secure bool        Set Secure flag on CSRF cookie (default false)
  --csrf-cookie-http-only bool     Set HttpOnly flag on CSRF cookie (default false)
  --csrf-cookie-same-site string   SameSite attribute for CSRF cookie (default default)
                                   Values: default, lax, strict, none

Healthcheck endpoints configuration options:
  --healthcheck-enabled bool                Enable health check endpoints (default false)
  --healthcheck-liveness-endpoint string    Path for the liveness health check endpoint that indicates if the application is running (default /livez)
  --healthcheck-readiness-endpoint string   Path for the readiness health check endpoint that indicates if the application is ready to receive traffic (default /readyz)
  --healthcheck-startup-endpoint string     Path for the startup health check endpoint that indicates if the application has completed its initialization (default /startupz)

Prometheus configuration options:
  --prometheus-enabled bool   Enables Prometheus metrics collection and exposure for application monitoring (default false)
  --prometheus-path string    Sets the HTTP path where Prometheus metrics will be exposed (default /metrics)

Rate limiter middleware configuration options:
  --ratelimiter-enabled bool                 Enable rate limiting middleware (default false)
  --ratelimiter-store string                 Storage backend for rate limiting (default memory)
                                             Values: memory
  --ratelimiter-memory-rate float64          Maximum request rate per time window (default 0)
  --ratelimiter-memory-burst int             Maximum number of requests allowed to exceed the rate (default 0)
  --ratelimiter-memory-expires-in duration   Time window for rate limit expiration (default 3m0s)

Recover middleware configuration options:
  --recover-enabled bool                 Enable automatic recovery from panics (default true)
  --recover-stack-size int               Controls the size of the stack trace buffer in kilobytes that will be captured when a panic occurs (default 4096)
  --recover-disable-stack-all bool       Disables capturing the complete stack trace during panic recovery (default false)
  --recover-disable-print-stack bool     Prevents printing the stack trace when recovering from panics (default false)
  --recover-disable-error-handler bool   Disables the default error handler for panics, allowing the application to crash instead of recovering (default false)

Redirect configuration options:
  --redirect-https bool   Controls whether HTTP requests are redirected to HTTPS (default false)
  --redirect-code int     Specifies the HTTP status code used for redirects (default 301)

Request ID middleware configuration options:
  --requestid-enabled bool           Enable request ID middleware (default true)
  --requestid-target-header string   Custom header for request ID (default X-Request-Id)

Security headers configuration options:
  --secure-enabled bool                                        Enables all security headers for enhanced protection against common web vulnerabilities (default false)
  --secure-content-security-policy string                      Sets the Content-Security-Policy header to help prevent cross-site scripting and other code injection attacks (default default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self';)
  --secure-content-security-policy-report-only bool            Enables report-only mode for CSP, which reports violations but doesn't enforce the policy (default false)
  --secure-cross-origin-embedder-policy string                 Controls which cross-origin resources can be loaded, default "require-corp" only allows resources that explicitly grant permission (default require-corp)
  --secure-cross-origin-opener-policy string                   Controls window interactions between origins, default "same-origin" restricts interactions to same-origin documents only (default same-origin)
  --secure-cross-origin-resource-policy string                 Specifies which origins can include your resources, default "same-origin" limits access to same-origin requests (default same-origin)
  --secure-permissions-policy string                           Controls which browser features and APIs can be used, default policy disables potentially sensitive features like camera, geolocation, and payment processing (default accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=())
  --secure-referrer-policy string                              Sets the Referrer-Policy header to control how much referrer information is included with requests (default no-referrer)
  --secure-server string                                       Sets a custom value for the HTTP Server header in responses
  --secure-strict-transport-security-max-age int               Sets the max age in seconds for the HTTP Strict-Transport-Security (HSTS) header (default 0)
  --secure-strict-transport-security-exclude-subdomains bool   Excludes subdomains from the HSTS policy, limiting it to the main domain only (default false)
  --secure-strict-transport-security-preload-enabled bool      Adds the preload directive to the HSTS header, allowing the site to be included in browser preload lists (default false)
  --secure-x-content-type-options string                       Sets the X-Content-Type-Options header to prevent MIME type sniffing (default nosniff)
  --secure-x-frame-options string                              Sets the X-Frame-Options header to prevent clickjacking attacks (default DENY)

Session middleware configuration options:
  --session-enabled bool                        Enables session management for maintaining user state across requests (default false)
  --session-store string                        Specifies the storage backend for session data (default cookie)
                                                Values: cookie, redis, redis-cluster, redis-sentinel
  --session-cookie-secret string                Sets the secret key used to sign and encrypt session cookies, this should be a strong, random value in production (default changeme)
  --session-redis-uri string                    Specifies the URI for connecting to a standalone Redis server for session storage (default redis://localhost:6379)
                                                Format: redis://[user:password@]host[:port][/database]
  --session-redis-cluster-uri string            Specifies the URI for connecting to a Redis Cluster deployment for session storage, multiple nodes can be separated by commas (default redis://localhost:6379)
  --session-redis-sentinel-master-name string   Specifies the name of the master node in a Redis Sentinel configuration (default mymaster)
  --session-redis-sentinel-addrs strings        Lists the addresses of Redis Sentinel nodes for high availability session storage (default [localhost:6379])

Static file serving configuration options:
  --static-enabled bool       Enables serving of static files from the specified directory (default false)
  --static-root string        Specifies the root directory from which to serve static files
  --static-index string       Sets the default file to serve when a directory is requested (default index.html)
  --static-html5 bool         Enables HTML5 mode which redirects all not-found requests to index.html for single-page applications (default false)
  --static-browse bool        Enables directory browsing when no index file is present (default false)
  --static-ignore-base bool   Ignores the base path when serving static files, useful when your app is mounted under a sub-path (default false)

Timeout middleware configuration options:
  --timeout-enabled bool           Enable request timeout middleware (default true)
  --timeout-error-message string   Custom error message when request times out (default Request timeout)
  --timeout-duration duration      Maximum duration allowed for request processing (default 15s)
```
