package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v10"
	"github.com/joho/godotenv"
)

type AppConfig struct {
	Port              string        `env:"PORT" envDefault:"8080"`
	GuardrailKey      string        `env:"GUARDRAIL_API_KEY,required"`
	AuditEnabled      bool          `env:"AUDIT_ENABLED" envDefault:"true"`
	AuditWorkers      int           `env:"AUDIT_WORKERS" envDefault:"4"`
	AuditBuffer       int           `env:"AUDIT_BUFFER" envDefault:"1024"`
	MaxConcurrent     int           `env:"MAX_CONCURRENT_CHECKS" envDefault:"32"`
	MaxBodyBytes      int64         `env:"MAX_BODY_BYTES" envDefault:"16777216"` // 16 MB
	AuthzCacheTTL     time.Duration `env:"AUTHZ_CACHE_TTL" envDefault:"60s"`
	RestrictedTerms   []string      `env:"RESTRICTED_TERMS" envSeparator:"," envDefault:"tsmc"`
	AllowedReadRoots  []string      `env:"ALLOWED_READ_ROOTS" envSeparator:"," envDefault:"/tmp,/var/tmp,/dev/null,/dev/stdin,/dev/stdout,/dev/stderr"`
	AllowedWriteRoots []string      `env:"ALLOWED_WRITE_ROOTS" envSeparator:"," envDefault:"/tmp,/var/tmp,/dev/null,/dev/stdout,/dev/stderr"`
}

type DBConfig struct {
	DBDriver string `env:"DB_DRIVER" envDefault:"postgres"`
	DBSource string `env:"DB_SOURCE,required"`
}

type Config struct {
	AppConfig `json:"app"`
	DBConfig  `json:"db"`
}

func NewConfig() (*Config, error) {
	_ = godotenv.Load()
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	return &cfg, nil
}
