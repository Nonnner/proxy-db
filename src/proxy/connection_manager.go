package proxy

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type BackendConn struct {
	conn      net.Conn
	inUse     bool
	createdAt time.Time
	lastUsed  time.Time
}

type ConnectionManager struct {
	mu          sync.Mutex
	host        string
	port        int
	maxConns    int
	conns       []*BackendConn
	dialTimeout time.Duration
}

func NewConnectionManager(host string, port int, maxConns int) *ConnectionManager {
	return &ConnectionManager{
		host:        host,
		port:        port,
		maxConns:    maxConns,
		dialTimeout: 10 * time.Second,
	}
}

func (cm *ConnectionManager) Get() (net.Conn, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for _, c := range cm.conns {
		if !c.inUse {
			c.inUse = true
			c.lastUsed = time.Now()
			return c.conn, nil
		}
	}

	if len(cm.conns) >= cm.maxConns {
		return nil, fmt.Errorf("connection pool exhausted (max %d)", cm.maxConns)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", cm.host, cm.port), cm.dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial backend: %w", err)
	}

	bc := &BackendConn{
		conn:      conn,
		inUse:     true,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}
	cm.conns = append(cm.conns, bc)
	return conn, nil
}

func (cm *ConnectionManager) Release(conn net.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for _, c := range cm.conns {
		if c.conn == conn {
			c.inUse = false
			c.lastUsed = time.Now()
			return
		}
	}
}

func (cm *ConnectionManager) Remove(conn net.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for i, c := range cm.conns {
		if c.conn == conn {
			c.conn.Close()
			cm.conns = append(cm.conns[:i], cm.conns[i+1:]...)
			return
		}
	}
}

func (cm *ConnectionManager) Close() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for _, c := range cm.conns {
		c.conn.Close()
	}
	cm.conns = nil
}
