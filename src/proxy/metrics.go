package proxy

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	proxyQPS = promauto.NewCounter(prometheus.CounterOpts{
		Name: "proxy_queries_total",
		Help: "Total number of queries processed",
	})

	queryRewriteLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "proxy_query_rewrite_latency_seconds",
		Help:    "Latency of query rewrite operations",
		Buckets: prometheus.DefBuckets,
	})

	cryptoLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "proxy_crypto_latency_seconds",
		Help:    "Latency of crypto operations",
		Buckets: prometheus.DefBuckets,
	})

	activeConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "proxy_active_connections",
		Help: "Number of active client connections",
	})

	encryptionErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "proxy_encryption_errors_total",
		Help: "Total number of encryption errors",
	})
)

// suppress unused variable warnings for metrics registered at init time
var _ = queryRewriteLatency
var _ = cryptoLatency
var _ = encryptionErrors
