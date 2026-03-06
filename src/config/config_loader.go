package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Proxy    ProxyConfig              `yaml:"proxy"`
	Database DatabaseConfig           `yaml:"database"`
	TLS      TLSConfig                `yaml:"tls"`
	KeyMgmt  KeyMgmtConfig            `yaml:"key_management"`
	Audit    AuditConfig              `yaml:"audit"`
	Tables   map[string]TablePolicy   `yaml:"tables"`
}

type ProxyConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	Protocol   string `yaml:"protocol"`
	MaxConns   int    `yaml:"max_connections"`
}

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"dbname"`
}

type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`
	ClientAuth bool   `yaml:"client_auth"`
}

type KeyMgmtConfig struct {
	Provider   string `yaml:"provider"`
	VaultAddr  string `yaml:"vault_addr"`
	VaultToken string `yaml:"vault_token"`
	KMSKeyID   string `yaml:"kms_key_id"`
	CacheTTL   int    `yaml:"cache_ttl_seconds"`
}

type AuditConfig struct {
	Enabled bool   `yaml:"enabled"`
	LogFile string `yaml:"log_file"`
}

type TablePolicy struct {
	Columns map[string]ColumnPolicy `yaml:"columns"`
}

type ColumnPolicy struct {
	Encryption string `yaml:"encryption"`
	KeyID      string `yaml:"key_id"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if cfg.Proxy.MaxConns == 0 {
		cfg.Proxy.MaxConns = 100
	}
	if cfg.Proxy.Protocol == "" {
		cfg.Proxy.Protocol = "mysql"
	}
	return &cfg, nil
}
