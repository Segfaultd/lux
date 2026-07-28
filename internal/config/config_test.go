package config

import (
	"os"
	"testing"
	"time"
)

var configEnvironment = []string{
	"LUX_LUMINA_ADDR", "LUX_HTTP_ADDR", "LUX_DATABASE", "LUX_SERVER_NAME",
	"LUX_USERNAME", "LUX_PASSWORD", "LUX_ADMIN_TOKEN", "LUX_ALLOW_DELETES",
	"LUX_HISTORY_LIMIT", "LUX_TLS_CERT", "LUX_TLS_KEY", "LUX_COMMAND_TIMEOUT",
	"LUX_HELLO_TIMEOUT", "LUX_PULL_TIMEOUT", "LUX_SHUTDOWN_TIMEOUT",
}

func TestParseDefaults(t *testing.T) {
	unsetConfigEnvironment(t)
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LuminaAddr != ":1234" || cfg.HTTPAddr != ":8080" || cfg.DatabasePath != "lux.db" {
		t.Fatalf("unexpected addresses/database: %#v", cfg)
	}
	if cfg.ServerName != "lux" || cfg.Username != "guest" || cfg.Password != "" {
		t.Fatalf("unexpected identity defaults: %#v", cfg)
	}
	if cfg.AllowDeletes || cfg.HistoryLimit != 50 {
		t.Fatalf("unexpected feature defaults: %#v", cfg)
	}
	if cfg.CommandWait != time.Hour || cfg.HelloWait != 15*time.Second ||
		cfg.PullWait != 4*time.Minute || cfg.ShutdownWait != 10*time.Second {
		t.Fatalf("unexpected timeout defaults: %#v", cfg)
	}
}

func TestParseEnvironmentAndFlagPrecedence(t *testing.T) {
	unsetConfigEnvironment(t)
	t.Setenv("LUX_LUMINA_ADDR", "127.0.0.1:2000")
	t.Setenv("LUX_HTTP_ADDR", "127.0.0.1:3000")
	t.Setenv("LUX_DATABASE", "environment.db")
	t.Setenv("LUX_SERVER_NAME", "environment")
	t.Setenv("LUX_USERNAME", "analyst")
	t.Setenv("LUX_PASSWORD", "password")
	t.Setenv("LUX_ADMIN_TOKEN", "token")
	t.Setenv("LUX_ALLOW_DELETES", "true")
	t.Setenv("LUX_HISTORY_LIMIT", "7")
	t.Setenv("LUX_TLS_CERT", "cert.pem")
	t.Setenv("LUX_TLS_KEY", "key.pem")
	t.Setenv("LUX_COMMAND_TIMEOUT", "2m")
	t.Setenv("LUX_HELLO_TIMEOUT", "3s")
	t.Setenv("LUX_PULL_TIMEOUT", "4s")
	t.Setenv("LUX_SHUTDOWN_TIMEOUT", "5s")

	cfg, err := Parse([]string{
		"-server-name", "flag",
		"-database", "flag.db",
		"-history-limit", "9",
		"-allow-deletes=false",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LuminaAddr != "127.0.0.1:2000" || cfg.HTTPAddr != "127.0.0.1:3000" {
		t.Fatalf("environment addresses not used: %#v", cfg)
	}
	if cfg.ServerName != "flag" || cfg.DatabasePath != "flag.db" ||
		cfg.HistoryLimit != 9 || cfg.AllowDeletes {
		t.Fatalf("flags did not override environment: %#v", cfg)
	}
	if cfg.Username != "analyst" || cfg.Password != "password" || cfg.AdminToken != "token" {
		t.Fatalf("environment identity not used: %#v", cfg)
	}
	if cfg.TLSCert != "cert.pem" || cfg.TLSKey != "key.pem" ||
		cfg.CommandWait != 2*time.Minute || cfg.HelloWait != 3*time.Second ||
		cfg.PullWait != 4*time.Second || cfg.ShutdownWait != 5*time.Second {
		t.Fatalf("environment TLS/timeouts not used: %#v", cfg)
	}
}

func TestParseValidation(t *testing.T) {
	unsetConfigEnvironment(t)
	tests := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"-does-not-exist"}},
		{"certificate without key", []string{"-tls-cert", "cert.pem"}},
		{"key without certificate", []string{"-tls-key", "key.pem"}},
		{"empty server name", []string{"-server-name", ""}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse(test.args); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestEnvironmentParsingFallbacks(t *testing.T) {
	t.Setenv("BOOL", "invalid")
	t.Setenv("UINT", "-1")
	t.Setenv("DURATION", "later")
	if envBool("BOOL", true) != true {
		t.Fatal("invalid bool did not use fallback")
	}
	if envUint("UINT", 12) != 12 {
		t.Fatal("invalid uint did not use fallback")
	}
	if envDuration("DURATION", time.Second) != time.Second {
		t.Fatal("invalid duration did not use fallback")
	}
	if env("MISSING_LUX_TEST_VALUE", "fallback") != "fallback" {
		t.Fatal("missing string did not use fallback")
	}
}

func unsetConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range configEnvironment {
		value, existed := os.LookupEnv(name)
		_ = os.Unsetenv(name)
		name, value := name, value
		t.Cleanup(func() {
			if existed {
				_ = os.Setenv(name, value)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}
