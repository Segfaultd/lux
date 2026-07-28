package config

import (
	"errors"
	"flag"
	"os"
	"strconv"
	"time"
)

type Config struct {
	LuminaAddr   string
	HTTPAddr     string
	DatabasePath string
	ServerName   string
	Username     string
	Password     string
	AdminToken   string
	AllowDeletes bool
	HistoryLimit uint
	TLSCert      string
	TLSKey       string
	CommandWait  time.Duration
	HelloWait    time.Duration
	PullWait     time.Duration
	ShutdownWait time.Duration
}

func Parse(args []string) (Config, error) {
	cfg := Config{}
	fs := flag.NewFlagSet("lux", flag.ContinueOnError)
	fs.StringVar(&cfg.LuminaAddr, "lumina-addr", env("LUX_LUMINA_ADDR", ":1234"), "Lumina TCP listen address")
	fs.StringVar(&cfg.HTTPAddr, "http-addr", env("LUX_HTTP_ADDR", ":8080"), "management HTTP listen address")
	fs.StringVar(&cfg.DatabasePath, "database", env("LUX_DATABASE", "lux.db"), "SQLite database path")
	fs.StringVar(&cfg.ServerName, "server-name", env("LUX_SERVER_NAME", "lux"), "name displayed to IDA clients")
	fs.StringVar(&cfg.Username, "username", env("LUX_USERNAME", "guest"), "Lumina login username")
	fs.StringVar(&cfg.Password, "password", env("LUX_PASSWORD", ""), "Lumina login password (empty accepts any password)")
	fs.StringVar(&cfg.AdminToken, "admin-token", env("LUX_ADMIN_TOKEN", ""), "token required for management mutations")
	fs.BoolVar(&cfg.AllowDeletes, "allow-deletes", envBool("LUX_ALLOW_DELETES", false), "allow delete-history RPC and web deletions")
	fs.UintVar(&cfg.HistoryLimit, "history-limit", envUint("LUX_HISTORY_LIMIT", 50), "maximum histories returned per function (0 disables)")
	fs.StringVar(&cfg.TLSCert, "tls-cert", env("LUX_TLS_CERT", ""), "PEM TLS certificate for Lumina (requires -tls-key)")
	fs.StringVar(&cfg.TLSKey, "tls-key", env("LUX_TLS_KEY", ""), "PEM TLS private key for Lumina (requires -tls-cert)")
	fs.DurationVar(&cfg.CommandWait, "command-timeout", envDuration("LUX_COMMAND_TIMEOUT", time.Hour), "idle client command timeout")
	fs.DurationVar(&cfg.HelloWait, "hello-timeout", envDuration("LUX_HELLO_TIMEOUT", 15*time.Second), "initial hello timeout")
	fs.DurationVar(&cfg.PullWait, "pull-timeout", envDuration("LUX_PULL_TIMEOUT", 4*time.Minute), "pull query timeout")
	fs.DurationVar(&cfg.ShutdownWait, "shutdown-timeout", envDuration("LUX_SHUTDOWN_TIMEOUT", 10*time.Second), "graceful shutdown timeout")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return Config{}, errors.New("both -tls-cert and -tls-key must be set together")
	}
	if cfg.ServerName == "" {
		return Config{}, errors.New("server name cannot be empty")
	}
	return cfg, nil
}

func env(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	v, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func envUint(name string, fallback uint) uint {
	v, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return fallback
	}
	return uint(parsed)
}

func envDuration(name string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return parsed
}
