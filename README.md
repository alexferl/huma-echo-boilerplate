# huma-echo-boilerplate [![Go Report Card](https://goreportcard.com/badge/github.com/alexferl/echo-boilerplate)](https://goreportcard.com/report/github.com/alexferl/echo-boilerplate)
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
```go
      --app-name string                              Application name (default "app")
      --bind-addr string                             Server binding address (default "127.0.0.1:1323")
      --body-limit string                            Sets the maximum allowed size of the request body. Use values like "100K", "10M" or "1G"
      --config-paths strings                         Specifies directories where configuration files will be searched for, in order of preference (default [./configs,/configs])
      --config-prefix string                         Sets the prefix for configuration files to be loaded, e.g., "config" would match "config.{env_name}.toml" (default "config")
      --config-type string                           Defines the format of configuration files to be loaded
                                                     Values: json, toml, or yaml (default "toml")
      --cors-allow-credentials                       Allow credentials in CORS requests
      --cors-allow-headers strings                   Allowed headers in CORS requests
      --cors-allow-methods strings                   Allowed HTTP methods in CORS request (default [GET,HEAD,PUT,PATCH,POST,DELETE])
      --cors-allow-origins strings                   Allowed origins for CORS requests (default [*])
      --cors-enabled                                 Enable CORS middleware
      --cors-expose-headers strings                  Headers exposed to browsers in CORS responses
      --cors-max-age int                             Max age (in seconds) for CORS preflight responses
      --csrf-context-key string                      Key used to store CSRF token in context (default "csrf")
      --csrf-cookie-domain string                    Domain attribute for CSRF cookie
      --csrf-cookie-http-only                        Set HttpOnly flag on CSRF cookie
      --csrf-cookie-max-age int                      Maximum age in seconds for CSRF cookie  (default 86400)
      --csrf-cookie-name string                      Name of the CSRF cookie (default "_csrf")
      --csrf-cookie-path string                      Path attribute for CSRF cookie
      --csrf-cookie-same-site string                 SameSite attribute for CSRF cookie
                                                     Values: default, lax, strict, node (default "default")
      --csrf-cookie-secure                           Set Secure flag on CSRF cookie
      --csrf-enabled                                 Enable CSRF protection middleware
      --csrf-token-length uint8                      Length of generated CSRF token in bytes (default 32)
      --csrf-token-lookup string                     Location to extract CSRF token from request (default "header:X-CSRF-Token")
      --env-name string                              Environment name (default "local")
      --graceful-timeout duration                    timeout (default 30s)
      --gzip-enabled                                 Enable GZIP compression
      --gzip-level int                               Compression level (default -1)
      --gzip-min-length int                          Minimum response size in bytes before compression is applied
      --healthcheck-enabled                          Enable health check endpoints (default true)
      --healthcheck-liveness-endpoint string         Path for the liveness health check endpoint that indicates if the application is running
      --healthcheck-readiness-endpoint string        Path for the readiness health check endpoint that indicates if the application is ready to receive traffic
      --healthcheck-startup-endpoint string          Path for the startup health check endpoint that indicates if the application has completed its initialization
      --log-level string                             Log granularity
                                                     Values: PANIC, FATAL, ERROR, WARN, INFO, DISABLED, TRACE, DISABLED (default "INFO")
      --log-output string                            Output destination
                                                     Values: stdout, stderr (default "stdout")
      --log-requests                                 Enables or disables logging of incoming HTTP requests (default true)
      --log-writer string                            Log format
                                                     Values: text, json (default "text")
      --prometheus-enabled                           Enables Prometheus metrics collection and exposure for application monitoring
      --prometheus-path string                       Sets the HTTP path where Prometheus metrics will be exposed (default "/metrics")
      --ratelimiter-enabled                          Enable rate limiting middleware
      --ratelimiter-memory-burst int                 Maximum number of requests allowed to exceed the rate
      --ratelimiter-memory-expires-in duration       Time window for rate limit expiration (default 3m0s)
      --ratelimiter-memory-rate float                Maximum request rate per time window
      --ratelimiter-store string                     Storage backend for rate limiting
                                                     Values: memory (default "memory")
      --recover-disable-error-handler                Disables the default error handler for panics, allowing the application to crash instead of recovering
      --recover-disable-print-stack                  Prevents printing the stack trace when recovering from panics
      --recover-disable-stack-all                    Disables capturing the complete stack trace during panic recovery
      --recover-enabled                              Enable automatic recovery from panics (default true)
      --recover-stack-size int                       recover (default 4096)
      --requestid-enabled                            Enable request ID middleware (default true)
      --requestid-target-header string               Custom header for request ID (default "X-Request-Id")
      --secure-content-security-policy string        Sets the Content-Security-Policy header to help prevent cross-site scripting and other code injection attacks
      --secure-content-security-policy-report-only   Enables report-only mode for CSP, which reports violations but doesn't enforce the policy
      --secure-content-type-no-sniff string          Sets the X-Content-Type-Options header to prevent MIME type sniffing (default "nosniff")
      --secure-enabled                               Enables all security headers for enhanced protection against common web vulnerabilities
      --secure-hsts-exclude-subdomains               Excludes subdomains from the HSTS policy, limiting it to the main domain only
      --secure-hsts-max-age int                      Sets the max age in seconds for the Strict-Transport-Security header
      --secure-hsts-preload-enabled                  Adds the preload directive to the HSTS header, allowing the site to be included in browser preload lists
      --secure-referrer-policy string                Sets the Referrer-Policy header to control how much referrer information is included with requests
      --secure-x-frame-options string                Sets the X-Frame-Options header to prevent clickjacking attacks (default "SAMEORIGIN")
      --secure-xss-protection string                 Sets the X-XSS-Protection header to enable browser's built-in XSS filtering (default "1; mode=block")
      --session-cookie-secret string                 Sets the secret key used to sign and encrypt session cookies, this should be a strong, random value in production (default "changeme")
      --session-enabled                              Enables session management for maintaining user state across requests
      --session-redis-cluster-uri string             Specifies the URI for connecting to a Redis Cluster deployment for session storage, multiple nodes can be separated by commas (default "redis://localhost:6379")
      --session-redis-sentinel-addrs strings         Lists the addresses of Redis Sentinel nodes for high availability session storage (default [localhost:6379])
      --session-redis-sentinel-master-name string    Specifies the name of the master node in a Redis Sentinel configuration (default "mymaster")
      --session-redis-uri string                     Specifies the URI for connecting to a standalone Redis server for session storage
                                                     Format: redis://[user:password@]host[:port][/database] (default "redis://localhost:6379")
      --session-store string                         Specifies the storage backend for session data
                                                     Values: cookie, redis, redis-cluster, redis-sentinel (default "cookie")
      --static-browse                                Enables directory browsing when no index file is present
      --static-enabled                               Enables serving of static files from the specified directory
      --static-html5                                 Enables HTML5 mode which redirects all not-found requests to index.html for single-page applications
      --static-ignore-base                           Ignores the base path when serving static files, useful when your app is mounted under a sub-path
      --static-index string                          Sets the default file to serve when a directory is requested (default "index.html")
      --static-root string                           Specifies the root directory from which to serve static files
      --timeout-enabled                              Enable request timeout middleware (default true)
      --timeout-error-message string                 Custom error message when request times out
      --timeout-time duration                        Maximum duration allowed for request processing
```
