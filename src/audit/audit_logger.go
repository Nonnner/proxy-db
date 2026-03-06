package audit

import (
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	logger  *zap.Logger
	enabled bool
}

type AuditEvent struct {
	Timestamp  time.Time
	EventType  string
	ClientAddr string
	Query      string
	Table      string
	Columns    []string
	KeyIDs     []string
	Duration   time.Duration
}

func NewLogger(enabled bool, logFile string) (*Logger, error) {
	if !enabled {
		nop := zap.NewNop()
		return &Logger{logger: nop, enabled: false}, nil
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	var core zapcore.Core
	if logFile != "" && logFile != "-" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		core = zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderCfg),
			zapcore.AddSync(f),
			zapcore.InfoLevel,
		)
	} else {
		core = zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderCfg),
			zapcore.AddSync(os.Stdout),
			zapcore.InfoLevel,
		)
	}

	return &Logger{
		logger:  zap.New(core),
		enabled: enabled,
	}, nil
}

func (l *Logger) LogEvent(event AuditEvent) {
	if !l.enabled {
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	l.logger.Info("audit_event",
		zap.String("event_type", event.EventType),
		zap.String("client_addr", event.ClientAddr),
		zap.String("query", event.Query),
		zap.String("table", event.Table),
		zap.Strings("columns", event.Columns),
		zap.Strings("key_ids", event.KeyIDs),
		zap.Duration("duration", event.Duration),
		zap.Time("timestamp", event.Timestamp),
	)
}

func (l *Logger) LogQueryRewrite(clientAddr, original, rewritten string) {
	if !l.enabled {
		return
	}
	l.logger.Info("query_rewritten",
		zap.String("client_addr", clientAddr),
		zap.String("original", original),
		zap.String("rewritten", rewritten),
	)
}

func (l *Logger) LogEncryption(clientAddr, table string, columns []string) {
	if !l.enabled {
		return
	}
	l.logger.Info("data_encrypted",
		zap.String("client_addr", clientAddr),
		zap.String("table", table),
		zap.Strings("columns", columns),
	)
}

func (l *Logger) LogKeyUsage(keyID string) {
	if !l.enabled {
		return
	}
	l.logger.Info("key_usage",
		zap.String("key_id", keyID),
	)
}
