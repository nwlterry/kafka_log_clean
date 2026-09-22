package clean

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type OmitRule struct {
	Type      string `yaml:"type"`
	Pattern   string `yaml:"pattern"`
	Path      string `yaml:"path"`
	Extension string `yaml:"extension"`
}

type ObfuscateRule struct {
	Type            string            `yaml:"type"`
	ReplacementType string            `yaml:"replacementType"`
	Target          string            `yaml:"target"`
	DomainNames     []string          `yaml:"domainNames"`
	Replacement     map[string]string `yaml:"replacement"`
	Regex           string            `yaml:"regex"`
	Pattern         string            `yaml:"pattern"`
	Replace         string            `yaml:"replace"`
	Enabled         *bool             `yaml:"enabled"`
}

type Config struct {
	Omit      []OmitRule      `yaml:"omit"`
	Obfuscate []ObfuscateRule `yaml:"obfuscate"`
}

type fileConfig struct {
	Config *Config `yaml:"config"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return ParseConfig(data)
}

func ParseConfig(data []byte) (Config, error) {
	var wrapped fileConfig
	if err := yaml.Unmarshal(data, &wrapped); err != nil {
		return Config{}, fmt.Errorf("parse yaml: %w", err)
	}
	if wrapped.Config != nil {
		return *wrapped.Config, nil
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse yaml: %w", err)
	}
	return cfg, nil
}

func DefaultConfig() Config {
	return Config{
		Omit: []OmitRule{
			{Type: "File", Pattern: "**/*.p12"},
			{Type: "File", Pattern: "**/*.jks"},
			{Type: "File", Pattern: "**/*.keystore"},
			{Type: "File", Pattern: "**/*.truststore"},
			{Type: "File", Pattern: "**/*.key"},
			{Type: "File", Pattern: "**/kafka_server_jaas.conf"},
		},
		Obfuscate: []ObfuscateRule{
			{Type: "IP", ReplacementType: "Consistent", Target: "All"},
			{Type: "MAC", ReplacementType: "Consistent", Target: "All"},
			{Type: "Email", ReplacementType: "Consistent", Target: "FileContents"},
			{Type: "Secrets", Enabled: boolPtr(true)},
			{Type: "PEM", Enabled: boolPtr(true)},
		},
	}
}

func boolPtr(v bool) *bool { return &v }
