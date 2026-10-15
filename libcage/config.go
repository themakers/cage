package libcage

import (
	"fmt"
	"os"
	"path"
	"strings"

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

// plaintextDirInCage validates a dirs path (relative to the cage root) and
// returns it relative to .cage/. Plaintext must live inside .cage/ (so that
// .cage/.gitignore, managed by cage, ignores it) and outside store/ and
// local/.
func plaintextDirInCage(rel string) (string, error) {
	clean := path.Clean(strings.ReplaceAll(rel, "\\", "/"))
	in, ok := strings.CutPrefix(clean, ".cage/")
	if !ok || in == "" || path.IsAbs(clean) {
		return "", fmt.Errorf("%q must be a directory inside .cage/ (plaintext secrets are git-ignored there)", rel)
	}
	for _, reserved := range []string{"store", "local"} {
		if in == reserved || strings.HasPrefix(in, reserved+"/") {
			return "", fmt.Errorf("%q: .cage/%s is reserved by cage", rel, reserved)
		}
	}
	return in, nil
}

func LoadConfig(p string) (*Config, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
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
	for alias, rel := range cfg.Dirs {
		if _, err := plaintextDirInCage(rel); err != nil {
			return nil, fmt.Errorf("dirs.%s: %w", alias, err)
		}
	}
	if cfg.Recipients == nil {
		cfg.Recipients = map[string][]string{}
	}
	if cfg.Envs == nil {
		cfg.Envs = map[string]Environment{}
	}
	return &cfg, nil
}
