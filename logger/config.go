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
	LogWriter string
}

var DefaultConfig = &Config{
	LogLevel:  InfoLevel,
	LogOutput: OutputStdOut,
	LogWriter: WriterText,
}

const (
	LogOutput = "log-output"
	LogWriter = "log-writer"
	LogLevel  = "log-level"
)

// BindFlags adds all the flags from the command line.
func (c *Config) BindFlags(fs *pflag.FlagSet) {
	fs.StringVar(&c.LogLevel, LogLevel, c.LogLevel,
		fmt.Sprintf("Log granularity\nValues: %s", strings.Join(Levels, ", ")),
	)
	fs.StringVar(&c.LogOutput, LogOutput, c.LogOutput,
		fmt.Sprintf("Output destination\nValues: %s", strings.Join(Outputs, ", ")),
	)
	fs.StringVar(&c.LogWriter, LogWriter, c.LogWriter,
		fmt.Sprintf("Log format\nValues: %s", strings.Join(Writers, ", ")),
	)
}
