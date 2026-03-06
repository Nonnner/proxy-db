package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nonnner/proxy-db/src/audit"
	"github.com/Nonnner/proxy-db/src/config"
	"github.com/Nonnner/proxy-db/src/protocol"
	"github.com/Nonnner/proxy-db/src/rewrite"
	"github.com/Nonnner/proxy-db/src/resultset"
)

type Server struct {
	config    *config.Config
	rewriter  *rewrite.RewriteEngine
	decryptor *resultset.DecryptPipeline
	audit     *audit.Logger
	connMgr   *ConnectionManager
	listener  net.Listener
	wg        sync.WaitGroup
	connCount atomic.Int64
	shutdown  chan struct{}
}

func NewServer(cfg *config.Config, rw *rewrite.RewriteEngine, dp *resultset.DecryptPipeline, al *audit.Logger) *Server {
	return &Server{
		config:    cfg,
		rewriter:  rw,
		decryptor: dp,
		audit:     al,
		connMgr:   NewConnectionManager(cfg.Database.Host, cfg.Database.Port, cfg.Proxy.MaxConns),
		shutdown:  make(chan struct{}),
	}
}

func (s *Server) Start() error {
	var l net.Listener
	var err error

	if s.config.TLS.Enabled {
		tlsCfg, err := loadTLSConfig(s.config.TLS)
		if err != nil {
			return fmt.Errorf("TLS config: %w", err)
		}
		l, err = tls.Listen("tcp", s.config.Proxy.ListenAddr, tlsCfg)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
	} else {
		l, err = net.Listen("tcp", s.config.Proxy.ListenAddr)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
	}
	s.listener = l

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

func (s *Server) Stop() error {
	close(s.shutdown)
	if s.listener != nil {
		s.listener.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
	s.connMgr.Close()
	return nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return
			default:
				continue
			}
		}
		if s.connCount.Load() >= int64(s.config.Proxy.MaxConns) {
			conn.Close()
			continue
		}
		s.connCount.Add(1)
		activeConnections.Inc()
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		s.connCount.Add(-1)
		activeConnections.Dec()
		s.wg.Done()
	}()

	s.audit.LogEvent(audit.AuditEvent{
		EventType:  "connection",
		ClientAddr: clientConn.RemoteAddr().String(),
	})

	backendConn, err := s.connMgr.Get()
	if err != nil {
		s.audit.LogEvent(audit.AuditEvent{
			EventType:  "connection_error",
			ClientAddr: clientConn.RemoteAddr().String(),
			Query:      err.Error(),
		})
		return
	}
	defer s.connMgr.Release(backendConn)

	rewriteFn := func(sql string) (string, error) {
		proxyQPS.Inc()
		rewritten, err := s.rewriter.Rewrite(sql)
		if err != nil {
			s.audit.LogQueryRewrite(clientConn.RemoteAddr().String(), sql, rewritten)
		}
		return rewritten, err
	}

	switch s.config.Proxy.Protocol {
	case "mssql":
		h := protocol.NewMSSQLHandler(clientConn, backendConn, rewriteFn)
		h.Handle()
	default:
		h := protocol.NewMySQLHandler(clientConn, backendConn, rewriteFn)
		h.Handle()
	}
}

func loadTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	if cfg.ClientAuth {
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg, nil
}
