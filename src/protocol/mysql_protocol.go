package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	comQuery = 0x03
	comQuit  = 0x01
	comPing  = 0x0e
)

type Packet struct {
	Length   uint32
	Sequence uint8
	Payload  []byte
}

func ReadPacket(r io.Reader) (*Packet, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16
	seq := header[3]
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return &Packet{Length: length, Sequence: seq, Payload: payload}, nil
}

func WritePacket(w io.Writer, seq uint8, payload []byte) error {
	header := make([]byte, 4)
	length := len(payload)
	header[0] = byte(length)
	header[1] = byte(length >> 8)
	header[2] = byte(length >> 16)
	header[3] = seq
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

type MySQLHandler struct {
	clientConn    net.Conn
	backendConn   net.Conn
	queryRewriter func(string) (string, error)
}

func NewMySQLHandler(client, backend net.Conn, rewriter func(string) (string, error)) *MySQLHandler {
	return &MySQLHandler{
		clientConn:    client,
		backendConn:   backend,
		queryRewriter: rewriter,
	}
}

func (h *MySQLHandler) Handle() error {
	if err := h.forwardHandshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	for {
		pkt, err := ReadPacket(h.clientConn)
		if err != nil {
			return nil
		}
		if len(pkt.Payload) == 0 {
			continue
		}
		cmd := pkt.Payload[0]
		switch cmd {
		case comQuit:
			if err := WritePacket(h.backendConn, pkt.Sequence, pkt.Payload); err != nil {
				return err
			}
			return nil
		case comQuery:
			query := string(pkt.Payload[1:])
			rewritten, err := h.queryRewriter(query)
			if err != nil {
				rewritten = query
			}
			newPayload := append([]byte{comQuery}, []byte(rewritten)...)
			if err := WritePacket(h.backendConn, pkt.Sequence, newPayload); err != nil {
				return err
			}
			if err := h.forwardResponse(); err != nil {
				return err
			}
		default:
			if err := WritePacket(h.backendConn, pkt.Sequence, pkt.Payload); err != nil {
				return err
			}
			if err := h.forwardResponse(); err != nil {
				return err
			}
		}
	}
}

func (h *MySQLHandler) forwardHandshake() error {
	pkt, err := ReadPacket(h.backendConn)
	if err != nil {
		return err
	}
	if err := WritePacket(h.clientConn, pkt.Sequence, pkt.Payload); err != nil {
		return err
	}
	authPkt, err := ReadPacket(h.clientConn)
	if err != nil {
		return err
	}
	if err := WritePacket(h.backendConn, authPkt.Sequence, authPkt.Payload); err != nil {
		return err
	}
	resultPkt, err := ReadPacket(h.backendConn)
	if err != nil {
		return err
	}
	return WritePacket(h.clientConn, resultPkt.Sequence, resultPkt.Payload)
}

func (h *MySQLHandler) forwardResponse() error {
	for {
		pkt, err := ReadPacket(h.backendConn)
		if err != nil {
			return err
		}
		if err := WritePacket(h.clientConn, pkt.Sequence, pkt.Payload); err != nil {
			return err
		}
		if isTerminatorPacket(pkt.Payload) {
			return nil
		}
	}
}

func isTerminatorPacket(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	return payload[0] == 0x00 || (payload[0] == 0xFE && len(payload) <= 5) || payload[0] == 0xFF
}

func LengthEncodedInt(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	switch data[0] {
	case 0xfb:
		return 0, 1
	case 0xfc:
		if len(data) < 3 {
			return 0, 0
		}
		return uint64(binary.LittleEndian.Uint16(data[1:3])), 3
	case 0xfd:
		if len(data) < 4 {
			return 0, 0
		}
		return uint64(data[1]) | uint64(data[2])<<8 | uint64(data[3])<<16, 4
	case 0xfe:
		if len(data) < 9 {
			return 0, 0
		}
		return binary.LittleEndian.Uint64(data[1:9]), 9
	default:
		return uint64(data[0]), 1
	}
}
