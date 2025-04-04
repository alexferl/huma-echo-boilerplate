package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/rs/zerolog/log"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/alexferl/huma-echo-boilerplate/config"
	"github.com/alexferl/huma-echo-boilerplate/service"
)

func main() {
	cfg := config.New()
	err := cfg.BindFlags()
	if err != nil {
		panic(err)
	}

	_, err = maxprocs.Set(maxprocs.Logger(log.Info().Msgf))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to set GOMAXPROCS")
	}

	cfg.Service.Name = cfg.AppName
	srv, err := service.New(cfg.Service)
	if err != nil {
		log.Fatal().Err(err).Msgf("failed to create %s service", cfg.AppName)
	}

	errCh := srv.Start()

	var endpoints []string
	if cfg.Service.TLS.Enabled {
		endpoints = append(endpoints, fmt.Sprintf("https://%s", cfg.Service.TLS.BindAddr))
		if cfg.Service.Redirect.HTTPS || cfg.Service.TLS.ACME.Enabled {
			endpoints = append(endpoints, fmt.Sprintf("http://%s", cfg.Service.BindAddr))
		}
	} else {
		endpoints = append(endpoints, fmt.Sprintf("http://%s", cfg.Service.BindAddr))
	}

	pid := os.Getpid()

	log.Info().
		Int("pid", pid).
		Msgf("%s started successfully, listening on %s", cfg.AppName, strings.Join(endpoints, " "))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Error().Err(err).Msgf("error in %s service", cfg.AppName)
		// continue to shut down logic regardless of error
	case <-sig:
		// signal received, proceed to shut down
	}

	log.Info().Msgf("%s shutting down", cfg.AppName)

	timeout := cfg.Service.GracefulTimeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("error during shutdown")
	}
}
