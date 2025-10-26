package protocol

import (
	"bytes"
	"encoding/binary"

	"trieutrng.com/toy-tls/helpers"
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

type CipherSuite uint16

const (
	TLS_AES_256_GCM_SHA384            CipherSuite = 0x0d02
	TLS_CHACHA20_POLY1305_SHA256      CipherSuite = 0x0d03
	TLS_AES_128_GCM_SHA256            CipherSuite = 0x0d01
	TLS_EMPTY_RENEGOTIATION_INFO_SCSV CipherSuite = 0x00ff
)

type HandShake struct {
	Type   HandshakeType
	Length int // the actual type is uint24 as RFC8446, using int as placeholder, would treat it as uint24 in the serializing and deserializing
	Body   ExchangeObject
}

func (h *HandShake) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, h.Type)
	buf.Write(helpers.MarshalUint24(h.Length))
	buf.Write(h.Body.Serialize())
	return buf.Bytes()
}

func (h *HandShake) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &h.Type)
	h.Length = helpers.UnmarshalUint24(buf.Next(3))

	h.Body = newHandshakeBody(h.Type)
	h.Body.Deserialize(buf.Next(h.Length))

	return len(data) - buf.Len()
}

func newHandshakeBody(handshakeType HandshakeType) ExchangeObject {
	switch handshakeType {
	case HandShake_ClientHello:
		return &ClientHello{}
	}
	return nil
}

type ClientHello struct {
	ProtocolVersion          ProtocolVersion
	Random                   []byte
	LegacySessionId          SessionID
	CipherSuites             CipherSuites
	LegacyCompressionMethods CompressionMethod
	Extensions               Extensions
}

func (c *ClientHello) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, c.ProtocolVersion)
	buf.Write(c.Random)
	buf.Write(c.LegacySessionId.Serialize())
	buf.Write(c.CipherSuites.Serialize())
	buf.Write(c.LegacyCompressionMethods.Serialize())
	buf.Write(c.Extensions.Serialize())
	return buf.Bytes()
}

func (c *ClientHello) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &c.ProtocolVersion)
	// random has 32 bytes
	c.Random = make([]byte, 32)
	copy(c.Random, buf.Next(32))
	c.LegacySessionId = SessionID{}
	c.CipherSuites = CipherSuites{}
	c.LegacyCompressionMethods = CompressionMethod{}
	c.Extensions = Extensions{}

	read := len(data) - buf.Len()
	read += c.LegacySessionId.Deserialize(data[read:])
	read += c.CipherSuites.Deserialize(data[read:])
	read += c.LegacyCompressionMethods.Deserialize(data[read:])
	read += c.Extensions.Deserialize(data[read:])

	return read
}

type SessionID struct {
	Length byte
	Data   []byte
}

func (s *SessionID) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, s.Length)
	buf.Write(s.Data)
	return buf.Bytes()
}

func (s *SessionID) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &s.Length)
	s.Data = make([]byte, s.Length)
	copy(s.Data, buf.Next(int(s.Length)))
	return len(data) - buf.Len()
}

type CipherSuites struct {
	Length       uint16
	CipherSuites []CipherSuite
}

func (s *CipherSuites) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, s.Length)
	for _, cipherSuite := range s.CipherSuites {
		_ = binary.Write(buf, binary.BigEndian, cipherSuite)
	}
	return buf.Bytes()
}

func (s *CipherSuites) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &s.Length)
	s.CipherSuites = make([]CipherSuite, 0)
	read := 0
	for read < int(s.Length) {
		var cipherSuite CipherSuite
		_ = binary.Read(buf, binary.BigEndian, &cipherSuite)
		s.CipherSuites = append(s.CipherSuites, cipherSuite)
		read += 2
	}
	return len(data) - buf.Len()
}

type CompressionMethod struct {
	Length byte
	Data   []byte
}

func (c *CompressionMethod) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, c.Length)
	buf.Write(c.Data)
	return buf.Bytes()
}

func (c *CompressionMethod) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &c.Length)
	c.Data = make([]byte, c.Length)
	copy(c.Data, buf.Next(int(c.Length)))
	return len(data) - buf.Len()
}
