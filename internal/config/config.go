package config

type Config struct {
	HTTPPort int
	GRPCPort int
	Env      string
}

func NewConfig() *Config {
	return &Config{
		HTTPPort: 8080,
		GRPCPort: 9090,
		Env:      "development",
	}
}
