package config

import "os"

type Config struct {
	HTTPPort int
	GRPCPort int
	Env      string
}

func NewConfig() *Config {
	env := os.Getenv("ENV")
	if env == "" {
		env = "local"
	}

	return &Config{
		HTTPPort: 8080,
		GRPCPort: 9090,
		Env:      env,
	}
}
