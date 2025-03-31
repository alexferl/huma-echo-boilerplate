package logger

import (
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	if DefaultConfig.LogLevel != InfoLevel {
		t.Errorf("Expected default LogLevel to be %s, got %s", InfoLevel, DefaultConfig.LogLevel)
	}

	if DefaultConfig.LogOutput != OutputStdOut {
		t.Errorf("Expected default LogOutput to be %s, got %s", OutputStdOut, DefaultConfig.LogOutput)
	}

	if DefaultConfig.LogWriter != WriterText {
		t.Errorf("Expected default LogWriter to be %s, got %s", WriterText, DefaultConfig.LogWriter)
	}
}

func TestConfig_FlagSet(t *testing.T) {
	tests := []struct {
		name         string
		config       *Config
		expectedName string
		flagChecks   []struct {
			flagName        string
			expectedValue   string
			expectedContent string
			expectedDesc    string
		}
	}{
		{
			name: "Custom config values",
			config: &Config{
				LogLevel:  "debug",
				LogOutput: "stderr",
				LogWriter: "json",
			},
			expectedName: "Logger",
			flagChecks: []struct {
				flagName        string
				expectedValue   string
				expectedContent string
				expectedDesc    string
			}{
				{
					flagName:        LogLevel,
					expectedValue:   "debug",
					expectedContent: strings.Join(Levels, ", "),
					expectedDesc:    "Log granularity",
				},
				{
					flagName:        LogOutput,
					expectedValue:   "stderr",
					expectedContent: strings.Join(Outputs, ", "),
					expectedDesc:    "Output destination",
				},
				{
					flagName:        LogWriter,
					expectedValue:   "json",
					expectedContent: strings.Join(Writers, ", "),
					expectedDesc:    "Log format",
				},
			},
		},
		{
			name:         "Default config values",
			config:       DefaultConfig,
			expectedName: "Logger",
			flagChecks: []struct {
				flagName        string
				expectedValue   string
				expectedContent string
				expectedDesc    string
			}{
				{
					flagName:        LogLevel,
					expectedValue:   InfoLevel,
					expectedContent: strings.Join(Levels, ", "),
					expectedDesc:    "Log granularity",
				},
				{
					flagName:        LogOutput,
					expectedValue:   OutputStdOut,
					expectedContent: strings.Join(Outputs, ", "),
					expectedDesc:    "Output destination",
				},
				{
					flagName:        LogWriter,
					expectedValue:   WriterText,
					expectedContent: strings.Join(Writers, ", "),
					expectedDesc:    "Log format",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := tt.config.FlagSet()

			if fs.Name() != tt.expectedName {
				t.Errorf("Expected FlagSet name to be '%s', got '%s'", tt.expectedName, fs.Name())
			}

			for _, check := range tt.flagChecks {
				flag := fs.Lookup(check.flagName)
				if flag == nil {
					t.Errorf("Expected %s flag to be registered", check.flagName)
					continue
				}

				if flag.DefValue != check.expectedValue {
					t.Errorf("Expected %s default value to be '%s', got '%s'",
						check.flagName, check.expectedValue, flag.DefValue)
				}

				if !strings.Contains(flag.Usage, check.expectedContent) {
					t.Errorf("Expected %s usage to contain '%s', got '%s'",
						check.flagName, check.expectedContent, flag.Usage)
				}

				if !strings.Contains(flag.Usage, check.expectedDesc) {
					t.Errorf("Expected %s usage to contain '%s', got '%s'",
						check.flagName, check.expectedDesc, flag.Usage)
				}
			}
		})
	}
}
