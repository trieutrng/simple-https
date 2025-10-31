package protocol

import (
	"bytes"
	"encoding/binary"

	"trieutrng.com/toy-tls/common"
	"trieutrng.com/toy-tls/helpers"
	"trieutrng.com/toy-tls/protocol/client"
	"trieutrng.com/toy-tls/protocol/server"
)

type HandShake struct {
	Type   common.HandshakeType
	Length int // the actual type is uint24 as RFC8446, using int as placeholder, would treat it as uint24 in the serializing and deserializing
	Body   common.ExchangeObject
}

func NewHandShake(handShakeType common.HandshakeType, body common.ExchangeObject) *HandShake {
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

func newHandshakeBody(handshakeType common.HandshakeType) common.ExchangeObject {
	switch handshakeType {
	case common.HandShake_ClientHello:
		return &ClientHello{}
	case common.HandShake_ServerHello:
		return &ServerHello{}
	case common.HandShake_EncryptedExtensions:
		return &server.Extensions{} // server only
	case common.HandShake_Certificate:
		return &Certificate{}
	case common.HandShake_CertificateVerify:
		return &CertificateVerify{}
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
	CipherSuites []common.CipherSuite
}

func NewCipherSuites(cipherSuites []common.CipherSuite) *CipherSuites {
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
	s.CipherSuites = make([]common.CipherSuite, 0)
	read := 0
	for read < int(s.Length) {
		var cipherSuite common.CipherSuite
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
	ProtocolVersion          common.ProtocolVersion
	Random                   []byte
	LegacySessionId          SessionID
	CipherSuites             CipherSuites
	LegacyCompressionMethods CompressionMethod
	Extensions               client.Extensions
}

func NewClientHello(protocolVersion common.ProtocolVersion, random []byte, sessionId *SessionID, cipherSuites *CipherSuites, compressionMethod *CompressionMethod, extensions *client.Extensions) *ClientHello {
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
	c.Extensions = client.Extensions{}

	read := len(data) - buf.Len()
	read += c.LegacySessionId.Deserialize(data[read:])
	read += c.CipherSuites.Deserialize(data[read:])
	read += c.LegacyCompressionMethods.Deserialize(data[read:])
	read += c.Extensions.Deserialize(data[read:])

	return read
}

type ServerHello struct {
	ProtocolVersion         common.ProtocolVersion
	Random                  []byte
	LegacySessionId         SessionID
	CipherSuite             common.CipherSuite
	LegacyCompressionMethod byte // always 0
	Extensions              server.Extensions
}

func NewServerHello(protocolVersion common.ProtocolVersion, random []byte, sessionId *SessionID, cipherSuite common.CipherSuite, extensions *server.Extensions) *ServerHello {
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

	s.CipherSuite = common.CipherSuite(uint16(data[read])<<8 | uint16(data[read+1]))
	read += 2

	s.LegacyCompressionMethod = data[read]
	read += 1

	s.Extensions = server.Extensions{}
	read += s.Extensions.Deserialize(data[read:])

	return read
}

type Certificate struct {
	RequestContext     CertificateRequestContext
	Length             int // the actual type is uint24 as RFC8446, using int as placeholder, would treat it as uint24 in the serializing and deserializing
	CertificateEntries []CertificateEntry
}

func (c *Certificate) Serialize() []byte {
	buf := new(bytes.Buffer)
	buf.Write(c.RequestContext.Serialize())

	certificateEntriesBuf := new(bytes.Buffer)
	for _, entry := range c.CertificateEntries {
		certificateEntriesBuf.Write(entry.Serialize())
	}
	certificateEntries := certificateEntriesBuf.Bytes()

	buf.Write(helpers.MarshalUint24(len(certificateEntries)))
	buf.Write(certificateEntries)

	return buf.Bytes()
}

func (c *Certificate) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)

	c.RequestContext = CertificateRequestContext{}
	buf.Next(c.RequestContext.Deserialize(data))

	c.Length = helpers.UnmarshalUint24(buf.Next(3))

	certEntriesData := buf.Next(c.Length)
	c.CertificateEntries = make([]CertificateEntry, 0)
	read := 0
	for read < len(certEntriesData) {
		certEntry := CertificateEntry{}
		read += certEntry.Deserialize(certEntriesData[read:])
		c.CertificateEntries = append(c.CertificateEntries, certEntry)
	}

	return len(data) - buf.Len()
}

type CertificateRequestContext struct {
	Length byte
	Data   []byte
}

func (c *CertificateRequestContext) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, c.Length)
	buf.Write(c.Data)
	return buf.Bytes()
}

func (c *CertificateRequestContext) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &c.Length)
	c.Data = make([]byte, c.Length)
	copy(c.Data, buf.Next(int(c.Length)))
	return len(data) - buf.Len()
}

type CertificateEntry struct {
	Length      int // the actual type is uint24 as RFC8446, using int as placeholder, would treat it as uint24 in the serializing and deserializing
	Certificate []byte
	Extensions  server.Extensions
}

func (c *CertificateEntry) Serialize() []byte {
	buf := new(bytes.Buffer)
	buf.Write(helpers.MarshalUint24(len(c.Certificate)))
	buf.Write(c.Certificate)
	buf.Write(c.Extensions.Serialize())
	return buf.Bytes()
}

func (c *CertificateEntry) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	c.Length = helpers.UnmarshalUint24(buf.Next(3))
	c.Certificate = make([]byte, c.Length)
	copy(c.Certificate, buf.Next(c.Length))

	c.Extensions = server.Extensions{}

	read := len(data) - buf.Len()
	read += c.Extensions.Deserialize(data[read:])

	return read
}

type CertificateVerify struct {
	SignatureAlgorithm common.SignatureAlgorithm
	Length             uint16
	Signature          []byte
}

func (c *CertificateVerify) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, c.SignatureAlgorithm)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(c.Signature)))
	buf.Write(c.Signature)
	return buf.Bytes()
}

func (c *CertificateVerify) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &c.SignatureAlgorithm)
	_ = binary.Read(buf, binary.BigEndian, &c.Length)
	c.Signature = make([]byte, c.Length)
	copy(c.Signature, buf.Next(int(c.Length)))
	return len(data) - buf.Len()
}
