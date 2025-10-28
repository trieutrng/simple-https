package protocol

import (
	"bytes"
	"encoding/binary"

	"trieutrng.com/toy-tls/helpers"
)

const ClientHelloRandomLength = 32

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
	TLS_AES_256_GCM_SHA384            CipherSuite = 0x1302
	TLS_CHACHA20_POLY1305_SHA256      CipherSuite = 0x1303
	TLS_AES_128_GCM_SHA256            CipherSuite = 0x1301
	TLS_EMPTY_RENEGOTIATION_INFO_SCSV CipherSuite = 0x00ff
)

type HandShake struct {
	Type   HandshakeType
	Length int // the actual type is uint24 as RFC8446, using int as placeholder, would treat it as uint24 in the serializing and deserializing
	Body   ExchangeObject
}

func NewHandShake(handShakeType HandshakeType, body ExchangeObject) *HandShake {
	return &HandShake{
		Type: handShakeType,
		Body: body,
	}
}

func (h *HandShake) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, h.Type)
	body := h.Body.Serialize()
	buf.Write(helpers.MarshalUint24(len(body)))
	buf.Write(body)

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
	case HandShake_ServerHello:
		return &ServerHello{}
	}
	return nil
}

type SessionID struct {
	Length byte
	Data   []byte
}

func NewSessionID(data []byte) *SessionID {
	return &SessionID{
		Data: data,
	}
}

func (s *SessionID) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, byte(len(s.Data)))
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

func NewCipherSuites(cipherSuites []CipherSuite) *CipherSuites {
	return &CipherSuites{
		CipherSuites: cipherSuites,
	}
}

func (s *CipherSuites) Serialize() []byte {
	buf := new(bytes.Buffer)

	cipherSuitesBuf := new(bytes.Buffer)
	for _, cipherSuite := range s.CipherSuites {
		_ = binary.Write(cipherSuitesBuf, binary.BigEndian, cipherSuite)
	}
	cipherSuites := cipherSuitesBuf.Bytes()
	_ = binary.Write(buf, binary.BigEndian, uint16(len(cipherSuites)))
	buf.Write(cipherSuites)

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

func NewCompressionMethod(data []byte) *CompressionMethod {
	return &CompressionMethod{
		Data: data,
	}
}

func (c *CompressionMethod) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, byte(len(c.Data)))
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

type ClientHello struct {
	ProtocolVersion          ProtocolVersion
	Random                   []byte
	LegacySessionId          SessionID
	CipherSuites             CipherSuites
	LegacyCompressionMethods CompressionMethod
	Extensions               Extensions
}

func NewClientHello(protocolVersion ProtocolVersion, random []byte, sessionId *SessionID, cipherSuites *CipherSuites, compressionMethod *CompressionMethod, extensions *Extensions) *ClientHello {
	return &ClientHello{
		ProtocolVersion:          protocolVersion,
		Random:                   random,
		LegacySessionId:          *sessionId,
		CipherSuites:             *cipherSuites,
		LegacyCompressionMethods: *compressionMethod,
		Extensions:               *extensions,
	}
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

type ServerHello struct {
	ProtocolVersion         ProtocolVersion
	Random                  []byte
	LegacySessionId         SessionID
	CipherSuite             CipherSuite
	LegacyCompressionMethod byte // always 0
	Extensions              Extensions
}

func NewServerHello(protocolVersion ProtocolVersion, random []byte, sessionId *SessionID, cipherSuite CipherSuite, extensions *Extensions) *ServerHello {
	return &ServerHello{
		ProtocolVersion:         protocolVersion,
		Random:                  random,
		LegacySessionId:         *sessionId,
		CipherSuite:             cipherSuite,
		LegacyCompressionMethod: 0,
		Extensions:              *extensions,
	}
}

func (s *ServerHello) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, s.ProtocolVersion)
	buf.Write(s.Random)
	buf.Write(s.LegacySessionId.Serialize())
	_ = binary.Write(buf, binary.BigEndian, s.CipherSuite)
	_ = binary.Write(buf, binary.BigEndian, byte(0)) // compression method, always 0 for server hello
	buf.Write(s.Extensions.Serialize())
	return buf.Bytes()
}

func (s *ServerHello) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &s.ProtocolVersion)

	// random has 32 bytes
	s.Random = make([]byte, 32)
	copy(s.Random, buf.Next(32))

	read := len(data) - buf.Len()

	s.LegacySessionId = SessionID{}
	read += s.LegacySessionId.Deserialize(data[read:])

	s.CipherSuite = CipherSuite(uint16(data[read])<<8 | uint16(data[read+1]))
	read += 2

	s.LegacyCompressionMethod = data[read]
	read += 1

	s.Extensions = Extensions{}
	read += s.Extensions.Deserialize(data[read:])

	return read
}
