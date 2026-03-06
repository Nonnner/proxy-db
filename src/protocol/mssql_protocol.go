package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	TDSPreLogin = 0x12
	TDSLogin7   = 0x10
	TDSSQLBatch = 0x01
	TDSResponse = 0x04
)

type TDSPacket struct {
	Type     byte
	Status   byte
	Length   uint16
	SPID     uint16
	PacketID byte
	Window   byte
	Payload  []byte
}

func ReadTDSPacket(r io.Reader) (*TDSPacket, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	pkt := &TDSPacket{
		Type:     header[0],
		Status:   header[1],
		Length:   binary.BigEndian.Uint16(header[2:4]),
		SPID:     binary.BigEndian.Uint16(header[4:6]),
		PacketID: header[6],
		Window:   header[7],
	}
	if pkt.Length < 8 {
		return nil, fmt.Errorf("TDS packet length %d < 8", pkt.Length)
	}
	payloadLen := int(pkt.Length) - 8
	pkt.Payload = make([]byte, payloadLen)
	if _, err := io.ReadFull(r, pkt.Payload); err != nil {
		return nil, err
	}
	return pkt, nil
}

func WriteTDSPacket(w io.Writer, pkt *TDSPacket) error {
	length := uint16(8 + len(pkt.Payload))
	header := make([]byte, 8)
	header[0] = pkt.Type
	header[1] = pkt.Status
	binary.BigEndian.PutUint16(header[2:4], length)
	binary.BigEndian.PutUint16(header[4:6], pkt.SPID)
	header[6] = pkt.PacketID
	header[7] = pkt.Window
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(pkt.Payload)
	return err
}

type MSSQLHandler struct {
	clientConn    net.Conn
	backendConn   net.Conn
	queryRewriter func(string) (string, error)
}

func NewMSSQLHandler(client, backend net.Conn, rewriter func(string) (string, error)) *MSSQLHandler {
	return &MSSQLHandler{
		clientConn:    client,
		backendConn:   backend,
		queryRewriter: rewriter,
	}
}

func (h *MSSQLHandler) Handle() error {
	if err := h.forwardMSSQLHandshake(); err != nil {
		return fmt.Errorf("mssql handshake: %w", err)
	}
	for {
		pkt, err := ReadTDSPacket(h.clientConn)
		if err != nil {
			return nil
		}
		if pkt.Type == TDSSQLBatch {
			query := extractSQLBatchQuery(pkt.Payload)
			rewritten, err := h.queryRewriter(query)
			if err != nil {
				rewritten = query
			}
			pkt.Payload = buildSQLBatchPayload(rewritten)
		}
		if err := WriteTDSPacket(h.backendConn, pkt); err != nil {
			return err
		}
		if err := h.forwardTDSResponse(); err != nil {
			return err
		}
	}
}

func (h *MSSQLHandler) forwardMSSQLHandshake() error {
	prePkt, err := ReadTDSPacket(h.clientConn)
	if err != nil {
		return err
	}
	if err := WriteTDSPacket(h.backendConn, prePkt); err != nil {
		return err
	}
	preResp, err := ReadTDSPacket(h.backendConn)
	if err != nil {
		return err
	}
	if err := WriteTDSPacket(h.clientConn, preResp); err != nil {
		return err
	}
	login, err := ReadTDSPacket(h.clientConn)
	if err != nil {
		return err
	}
	if err := WriteTDSPacket(h.backendConn, login); err != nil {
		return err
	}
	loginResp, err := ReadTDSPacket(h.backendConn)
	if err != nil {
		return err
	}
	return WriteTDSPacket(h.clientConn, loginResp)
}

func (h *MSSQLHandler) forwardTDSResponse() error {
	for {
		pkt, err := ReadTDSPacket(h.backendConn)
		if err != nil {
			return err
		}
		if err := WriteTDSPacket(h.clientConn, pkt); err != nil {
			return err
		}
		if pkt.Status&0x01 != 0 {
			return nil
		}
	}
}

func extractSQLBatchQuery(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	allHeadersLen := int(binary.LittleEndian.Uint32(payload[:4]))
	if allHeadersLen >= len(payload) {
		return ""
	}
	sqlBytes := payload[allHeadersLen:]
	if len(sqlBytes)%2 != 0 {
		sqlBytes = sqlBytes[:len(sqlBytes)-1]
	}
	runes := make([]rune, len(sqlBytes)/2)
	for i := range runes {
		runes[i] = rune(binary.LittleEndian.Uint16(sqlBytes[i*2:]))
	}
	return string(runes)
}

func buildSQLBatchPayload(sql string) []byte {
	header := []byte{4, 0, 0, 0}
	sqlRunes := []rune(sql)
	sqlBytes := make([]byte, len(sqlRunes)*2)
	for i, r := range sqlRunes {
		binary.LittleEndian.PutUint16(sqlBytes[i*2:], uint16(r))
	}
	return append(header, sqlBytes...)
}
