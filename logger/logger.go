package logger

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	PanicLevel = "PANIC"
	FatalLevel = "FATAL"
	ErrorLevel = "ERROR"
	WarnLevel  = "WARN"
	InfoLevel  = "INFO"
	DebugLevel = "DEBUG"
	TraceLevel = "TRACE"
	Disabled   = "DISABLED"
)

var Levels = []string{PanicLevel, FatalLevel, ErrorLevel, WarnLevel, InfoLevel, Disabled, TraceLevel, Disabled}

const (
	FormatText = "text"
	FormatJSON = "json"
)

var Formats = []string{FormatText, FormatJSON}

const (
	OutputStdOut = "stdout"
	OutputStdErr = "stderr"
)

var Outputs = []string{OutputStdOut, OutputStdErr}

// New initializes the logger based on the passed Config,
// defaults to DefaultConfig if `config` is nil.
func New(config *Config) error {
	if config == nil {
		config = DefaultConfig
	}

	if config.LogLevel == "" {
		config.LogLevel = DefaultConfig.LogLevel
	}

	if config.LogOutput == "" {
		config.LogOutput = DefaultConfig.LogOutput
	}

	if config.LogFormat == "" {
		config.LogFormat = DefaultConfig.LogFormat
	}

	logOutput := strings.ToLower(config.LogOutput)
	logFormat := strings.ToLower(config.LogFormat)
	logLevel := strings.ToUpper(config.LogLevel)

	var f *os.File
	switch logOutput {
	case OutputStdOut:
		f = os.Stdout
	case OutputStdErr:
		f = os.Stderr
	default:
		return fmt.Errorf("unknown %s '%s'", LogOutput, logOutput)
	}

	logger := zerolog.New(f)

	switch logFormat {
	case FormatText:
		logger = log.Output(zerolog.ConsoleWriter{
			Out: f, TimeFormat: time.RFC3339Nano,
		})
	case FormatJSON:
		break
	default:
		return fmt.Errorf("unknown %s '%s'", LogFormat, logFormat)
	}

	log.Logger = logger.With().Timestamp().Caller().Logger()

	switch logLevel {
	case PanicLevel:
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	case FatalLevel:
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case ErrorLevel:
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case WarnLevel:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case InfoLevel:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case DebugLevel:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case TraceLevel:
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case Disabled:
		zerolog.SetGlobalLevel(zerolog.Disabled)
	default:
		return fmt.Errorf("unknown %s '%s'", LogLevel, logLevel)
	}

	return nil
}
