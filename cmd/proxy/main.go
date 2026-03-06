package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/Nonnner/proxy-db/src/audit"
	"github.com/Nonnner/proxy-db/src/config"
	cryptopkg "github.com/Nonnner/proxy-db/src/crypto"
	"github.com/Nonnner/proxy-db/src/key_management"
	"github.com/Nonnner/proxy-db/src/policy"
	"github.com/Nonnner/proxy-db/src/proxy"
	"github.com/Nonnner/proxy-db/src/resultset"
	"github.com/Nonnner/proxy-db/src/rewrite"
)

func main() {
	configFile := flag.String("config", "configs/proxy.yaml", "path to config file")
	metricsAddr := flag.String("metrics-addr", ":9090", "prometheus metrics address")
	flag.Parse()

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	cfg, err := config.Load(*configFile)
	if err != nil {
		logger.Fatal("failed to load config", zap.Error(err))
	}

	var km key_management.KeyManager
	ttl := time.Duration(cfg.KeyMgmt.CacheTTL) * time.Second
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	switch cfg.KeyMgmt.Provider {
	case "vault":
		km = key_management.NewVaultKeyManager(cfg.KeyMgmt.VaultAddr, cfg.KeyMgmt.VaultToken, ttl)
	default:
		km = key_management.NewLocalKeyManager(ttl)
	}

	enc := cryptopkg.NewEncryptionEngine()
	enc.Register(&cryptopkg.AESModule{})
	enc.Register(&cryptopkg.DeterministicModule{})
	enc.Register(&cryptopkg.FPEModule{})

	pol := policy.NewPolicy(cfg.Tables)

	al, err := audit.NewLogger(cfg.Audit.Enabled, cfg.Audit.LogFile)
	if err != nil {
		logger.Fatal("failed to create audit logger", zap.Error(err))
	}

	rw := rewrite.NewRewriteEngine(pol, enc, km)
	dp := resultset.NewDecryptPipeline(pol, enc, km)
	srv := proxy.NewServer(cfg, rw, dp, al)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	httpSrv := &http.Server{Addr: *metricsAddr, Handler: mux}
	go func() {
		logger.Info("metrics server listening", zap.String("addr", *metricsAddr))
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server error", zap.Error(err))
		}
	}()

	if err := srv.Start(); err != nil {
		logger.Fatal("failed to start proxy", zap.Error(err))
	}
	logger.Info("proxy started", zap.String("addr", cfg.Proxy.ListenAddr), zap.String("protocol", cfg.Proxy.Protocol))

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	logger.Info("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	httpSrv.Shutdown(ctx)
	srv.Stop()
	logger.Info("shutdown complete")
}
