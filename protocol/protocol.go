package protocol

import (
	"bytes"
	"encoding/binary"
)

type RecordContentType uint8

const (
	Record_Invalid          RecordContentType = 0x00
	Record_ChangeCipherSpec RecordContentType = 0x14
	Record_Alert            RecordContentType = 0x15
	Record_Handshake        RecordContentType = 0x16
	Record_ApplicationData  RecordContentType = 0x17
	Record_Heartbeat        RecordContentType = 0x18
)

// protocol version
type ProtocolVersion uint16

const (
	TLS_1_0 ProtocolVersion = 0x0301
	TLS_1_2 ProtocolVersion = 0x0303
	TLS_1_3 ProtocolVersion = 0x0304
)

// handshake type
type HandshakeType uint8

const (
	HandShake_ClientHello         HandshakeType = 0x01
	HandShake_ServerHello         HandshakeType = 0x02
	HandShake_EncryptedExtensions HandshakeType = 0x08
	HandShake_Certificate         HandshakeType = 0x0b
	HandShake_CertificateRequest  HandshakeType = 0x0d
	HandShake_CertificateVerify   HandshakeType = 0x0f
	HandShake_Finished            HandshakeType = 0x14
)

type ExchangeObject interface {
	Serialize() []byte
	Deserialize([]byte) int
}

type Record struct {
	Type            uint8
	ProtocolVersion uint16
	Length          uint16
	Fragment        ExchangeObject
}

func (r *Record) Serialize() []byte {
	buf := new(bytes.Buffer)

	// type
	_ = binary.Write(buf, binary.BigEndian, r.Type)

	// protocol version
	_ = binary.Write(buf, binary.BigEndian, r.ProtocolVersion)

	//
	fragment := r.Fragment.Serialize()
	// length
	_ = binary.Write(buf, binary.BigEndian, len(fragment))

	// fragment
	buf.Write(fragment)

	return buf.Bytes()
}

func (r *Record) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &r.Type)
	_ = binary.Read(buf, binary.BigEndian, &r.ProtocolVersion)
	_ = binary.Read(buf, binary.BigEndian, &r.Length)

	// fragment
	r.Fragment.Deserialize(buf.Next(int(r.Length)))

	return 0 // TODO
}

type HandShake struct {
	Type   uint8
	Length uint16
	Body   ExchangeObject
}

func (h *HandShake) Serialize() []byte {
	buf := new(bytes.Buffer)

	// handshake type
	_ = binary.Write(buf, binary.BigEndian, h.Type)

	//
	body := h.Body.Serialize()
	// Length
	_ = binary.Write(buf, binary.BigEndian, len(body))
	// Body
	buf.Write(body)

	return buf.Bytes()
}

func (h *HandShake) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &h.Type)
	_ = binary.Read(buf, binary.BigEndian, &h.Length)
	// body
	h.Body.Deserialize(buf.Next(int(h.Length)))
	return 0 // TODO
}

type SessionID struct {
	Length byte
	Data   []byte
}

func (s *SessionID) Serialize() []byte {
	return nil // TODO
}

func (s *SessionID) Deserialize(data []byte) int {
	return 0 // TODO
}

type CipherSuites struct {
	Length uint16
	Data   []uint16
}

func (s *CipherSuites) Serialize() []byte {
	return nil // TODO
}

func (s *CipherSuites) Deserialize(data []byte) int {
	return 0 // TODO
}

type CompressionMethod struct {
	Length byte
	Data   []byte
}

func (c *CompressionMethod) Serialize() []byte {
	return nil // TODO
}

func (c *CompressionMethod) Deserialize(data []byte) int {
	return 0 // TODO
}

type ClientHello struct {
	ProtocolVersion          uint16
	Random                   []byte
	LegacySessionId          SessionID
	CipherSuites             CipherSuites
	LegacyCompressionMethods CompressionMethod
	Extensions               Extensions
}

//func (c *ClientHello) Serialize() []byte {
//	buf := new(bytes.Buffer)
//
//	// protocol version
//	_ = binary.Write(buf, binary.BigEndian, c.ProtocolVersion)
//	// random
//	_ = binary.Write(buf, binary.BigEndian, c.Random)
//	// legacy session id
//	buf.Write(c.LegacySessionId.Serialize())
//
//	// cipher suites
//	for _, cps := range c.CipherSuites {
//		_ = binary.Write(buf, binary.BigEndian, cps)
//	}
//	// legacy compression methods
//	_ = binary.Write(buf, binary.BigEndian, c.LegacyCompressionMethods)
//
//	// extensions
//	extBuf := new(bytes.Buffer)
//	for _, ext := range c.Extensions {
//		extBuf.Write(ext.Serialize())
//	}
//	_ = binary.Write(buf, binary.BigEndian, uint16(extBuf.Len()))
//	_ = binary.Write(buf, binary.BigEndian, extBuf.Bytes())
//
//	return buf.Bytes()
//}
//
//func (c *ClientHello) Deserialize(data []byte) int {
//	buf := bytes.NewBuffer(data)
//
//	_ = binary.Read(buf, binary.BigEndian, &c.ProtocolVersion)
//
//	// random has 32 bytes
//	c.Random = make([]byte, buf.Len())
//	copy(c.Random, buf.Next(32))
//
//	// legacy session id
//	sessionIdLength := uint16(0)
//	_ = binary.Read(buf, binary.BigEndian, &sessionIdLength)
//	c.LegacySessionId = make([]byte, sessionIdLength)
//	copy(c.LegacySessionId, buf.Next(int(sessionIdLength)))
//
//	// cipher suites
//	cipherSuiteLength := uint16(0)
//	_ = binary.Read(buf, binary.BigEndian, &cipherSuiteLength)
//	c.LegacySessionId = make([]byte, sessionIdLength)
//	copy(c.LegacySessionId, buf.Next(int(sessionIdLength)))
//}
