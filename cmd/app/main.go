package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
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

	appName := viper.GetString(config.AppName)
	srv, err := service.New()
	if err != nil {
		log.Fatal().Err(err).Msgf("failed creating %s service", appName)
	}

	errCh := srv.Start()

	log.Info().Msgf(
		"%s started successfully, listening on http://%s",
		appName, viper.GetString(config.BindAddr),
	)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Fatal().Err(err).Msgf("failed starting %s service", appName)
	case <-sig:
		log.Info().Msgf("signal received, %s shutting down", viper.GetString(config.AppName))

		timeout := viper.GetDuration(config.GracefulTimeout)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Fatal().Err(err).Send()
		}
	}
}
