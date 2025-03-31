package logger

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

// Config holds all log configuration.
type Config struct {
	LogLevel  string
	LogOutput string
	LogFormat string
}

var DefaultConfig = &Config{
	LogLevel:  InfoLevel,
	LogOutput: OutputStdOut,
	LogFormat: FormatText,
}

const (
	LogOutput = "log-output"
	LogFormat = "log-format"
	LogLevel  = "log-level"
)

func (c *Config) FlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("Logger", pflag.ExitOnError)
	fs.StringVar(&c.LogLevel, LogLevel, c.LogLevel,
		fmt.Sprintf("Log granularity\nValues: %s", strings.Join(Levels, ", ")),
	)
	fs.StringVar(&c.LogFormat, LogFormat, c.LogFormat,
		fmt.Sprintf("Log format\nValues: %s", strings.Join(Formats, ", ")),
	)
	fs.StringVar(&c.LogOutput, LogOutput, c.LogOutput,
		fmt.Sprintf("Output destination\nValues: %s", strings.Join(Outputs, ", ")),
	)

	return fs
}
