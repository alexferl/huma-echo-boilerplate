package logger

import (
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestNew(t *testing.T) {
	tests := []struct {
		config *Config
		fail   bool
	}{
		{nil, false},
		{DefaultConfig, false},
		{&Config{LogLevel: WarnLevel, LogOutput: OutputStdOut, LogFormat: FormatJSON}, false},
		{&Config{LogLevel: InfoLevel, LogOutput: OutputStdErr, LogFormat: FormatJSON}, false},
		{&Config{LogLevel: InfoLevel, LogOutput: OutputStdOut, LogFormat: FormatText}, false},
		{&Config{LogLevel: PanicLevel, LogOutput: OutputStdOut, LogFormat: FormatJSON}, false},
		{&Config{LogLevel: FatalLevel, LogOutput: OutputStdOut, LogFormat: FormatJSON}, false},
		{&Config{LogLevel: ErrorLevel, LogOutput: OutputStdOut, LogFormat: FormatJSON}, false},
		{&Config{LogLevel: WarnLevel, LogOutput: OutputStdOut, LogFormat: FormatJSON}, false},
		{&Config{LogLevel: DebugLevel, LogOutput: OutputStdOut, LogFormat: FormatJSON}, false},
		{&Config{LogLevel: TraceLevel, LogOutput: OutputStdOut, LogFormat: FormatJSON}, false},
		{&Config{LogLevel: Disabled, LogOutput: OutputStdOut, LogFormat: FormatJSON}, false},
		{&Config{LogLevel: ""}, false},
		{&Config{LogLevel: "wrong"}, true},
		{&Config{LogLevel: InfoLevel, LogOutput: "wrong"}, true},
		{&Config{LogLevel: InfoLevel, LogOutput: OutputStdOut, LogFormat: "wrong"}, true},
	}

	for _, tc := range tests {
		err := New(tc.config)
		if !tc.fail {
			if err != nil {
				t.Errorf("%v", err)
			}

			level := strings.ToUpper(zerolog.GlobalLevel().String())
			if tc.config != nil && tc.config.LogLevel != level {
				t.Errorf("got %s expected %s", tc.config.LogLevel, level)
			}
		} else {
			if err == nil {
				t.Error("test did not error")
			}
		}
	}
}
