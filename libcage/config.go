package libcage

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Kind       string                 `yaml:"kind"`
	Dirs       map[string]string      `yaml:"dirs"`
	Recipients map[string][]string    `yaml:"recipients"`
	Envs       map[string]Environment `yaml:"envs"`
}

type Environment struct {
	Files      []string `yaml:"files"`
	Recipients []string `yaml:"recipients"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Kind != "cage/v1" {
		return nil, fmt.Errorf("unsupported config kind %q (expected cage/v1)", cfg.Kind)
	}
	if cfg.Dirs == nil {
		cfg.Dirs = map[string]string{}
	}
	if _, ok := cfg.Dirs["default"]; !ok {
		// "default" is required because it affects parsing of secret refs
		return nil, fmt.Errorf("config dirs must define alias \"default\"")
	}
	if cfg.Recipients == nil {
		cfg.Recipients = map[string][]string{}
	}
	if cfg.Envs == nil {
		cfg.Envs = map[string]Environment{}
	}
	return &cfg, nil
}
