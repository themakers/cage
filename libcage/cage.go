package libcage

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type Cage struct {
	Logger *slog.Logger

	// Root is the directory that contains the .cage directory.
	// Empty Root means "raw" mode: operations work only with explicit *.cage files.
	Root string

	Cfg *Config
	Ids Identities
}

type NewOptions struct {
	Root       string
	Logger     *slog.Logger
	Identities *Identities // optional; if nil, discovery is performed
}

func New(opts NewOptions) (*Cage, error) {
	lg := opts.Logger
	if lg == nil {
		lg = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	c := &Cage{Logger: lg, Root: opts.Root}

	if opts.Identities != nil {
		c.Ids = *opts.Identities
	} else {
		ids, err := DiscoverIdentities(DiscoverOptions{Logger: lg})
		if err != nil {
			// discovery errors are not fatal; only missing usable identities is
			// fatal for decrypt-like operations.
			lg.Warn("identity discovery error", "err", err)
		}
		c.Ids = ids
	}

	if c.Root != "" {
		cfg, err := LoadConfig(filepath.Join(c.Root, ".cage", "cage.yaml"))
		if err != nil {
			return nil, err
		}
		c.Cfg = cfg
	}

	return c, nil
}

func IsEnvSecretName(name string) bool {
	return strings.HasSuffix(name, ".env")
}
