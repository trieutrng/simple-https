package protocol

import (
	"bytes"
	"encoding/binary"
)

type ExtensionType uint16

const (
	Ext_ServerName          ExtensionType = 0x00
	Ext_SupportedGroups     ExtensionType = 0x0a
	Ext_SignatureAlgorithms ExtensionType = 0x0d
	Ext_KeyShare            ExtensionType = 0x33
	Ext_PSKKeyExchangeModes ExtensionType = 0x2d
	Ext_SupportedVersions   ExtensionType = 0x2b
)

type ServerNameType byte

const (
	Host_Name ServerNameType = 0
)

type NamedCurve uint16

const (
	X25519 NamedCurve = 0x001d
)

type SignatureAlgorithms uint16

const (
	ECDSA_SECP256R1_SHA256 SignatureAlgorithms = 0x0403
	ECDSA_SECP384R1_SHA384 SignatureAlgorithms = 0x0503
	ECDSA_SECP521R1_SHA512 SignatureAlgorithms = 0x0603
	ED25519                SignatureAlgorithms = 0x0807
	ED448                  SignatureAlgorithms = 0x0808
	RSA_PSS_PSS_SHA256     SignatureAlgorithms = 0x0809
	RSA_PSS_PSS_SHA384     SignatureAlgorithms = 0x080a
	RSA_PSS_PSS_SHA512     SignatureAlgorithms = 0x080b
	RSA_PSS_RSAE_SHA256    SignatureAlgorithms = 0x0804
	RSA_PSS_RSAE_SHA384    SignatureAlgorithms = 0x0805
	RSA_PSS_RSAE_SHA512    SignatureAlgorithms = 0x0806
	RSA_PKCS1_SHA256       SignatureAlgorithms = 0x0401
	RSA_PKCS1_SHA384       SignatureAlgorithms = 0x0501
	RSA_PKCS1_SHA512       SignatureAlgorithms = 0x0601
)

type PSKKeyExchangeMode uint8

const (
	PSK_DHE_KE PSKKeyExchangeMode = 0x01
)

type Extensions struct {
	Length uint16
	Data   []Extension
}

func (e *Extensions) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, e.Length)
	for _, ext := range e.Data {
		_ = binary.Write(buf, binary.BigEndian, ext.Serialize())
	}
	return buf.Bytes()
}

func (e *Extensions) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &e.Length)
	extData := buf.Next(int(e.Length))
	e.Data = make([]Extension, 0)
	read := 0
	for read < len(extData) {
		ext := Extension{}
		read += ext.Deserialize(extData[read:])
		e.Data = append(e.Data, ext)
	}
	return len(data) - buf.Len()
}

type Extension struct {
	Type   ExtensionType
	Length uint16
	Data   ExchangeObject
}

func (e *Extension) Serialize() []byte {
	buf := new(bytes.Buffer)
	// type
	_ = binary.Write(buf, binary.BigEndian, e.Type)
	// length
	_ = binary.Write(buf, binary.BigEndian, e.Length)
	// data
	buf.Write(e.Data.Serialize())

	return buf.Bytes()
}

func (e *Extension) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	// type
	_ = binary.Read(buf, binary.BigEndian, &e.Type)
	// length
	_ = binary.Read(buf, binary.BigEndian, &e.Length)

	// data
	e.Data = NewExtension(ExtensionType(e.Type))
	e.Data.Deserialize(buf.Next(int(e.Length)))

	return len(data) - buf.Len()
}

func NewExtension(extType ExtensionType) ExchangeObject {
	switch extType {
	case Ext_ServerName:
		return &ExtServerNameList{}
	case Ext_SupportedGroups:
		return &ExtSupportedGroups{}
	case Ext_SignatureAlgorithms:
		return &ExtSignatureAlgorithms{}
	case Ext_KeyShare:
		return &ExtKeyShare{}
	case Ext_PSKKeyExchangeModes:
		return &ExtPSKKeyExchangeModes{}
	case Ext_SupportedVersions:
		return &ExtSupportedVersions{}
	}

	return nil
}

// Extension: ServerName
type ExtServerNameList struct {
	Length     uint16
	ServerName ServerName
}

func (e *ExtServerNameList) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, e.Length)
	_ = binary.Write(buf, binary.BigEndian, e.ServerName.Serialize())
	return buf.Bytes()
}

func (e *ExtServerNameList) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &e.Length)
	e.ServerName = ServerName{}
	e.ServerName.Deserialize(buf.Next(int(e.Length)))
	return len(data) - buf.Len()
}

type ServerName struct {
	NameType ServerNameType
	Length   uint16
	Data     []byte
}

func (s *ServerName) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, s.NameType)
	_ = binary.Write(buf, binary.BigEndian, s.Length)
	buf.Write(s.Data)
	return buf.Bytes()
}

func (s *ServerName) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &s.NameType)
	_ = binary.Read(buf, binary.BigEndian, &s.Length)
	s.Data = make([]byte, s.Length)
	copy(s.Data, buf.Next(int(s.Length)))
	return len(data) - buf.Len()
}

// Extension: SupportedGroups
type ExtSupportedGroups struct {
	Length     uint16
	NamedCurve []NamedCurve
}

func (e *ExtSupportedGroups) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, e.Length)
	for _, curve := range e.NamedCurve {
		_ = binary.Write(buf, binary.BigEndian, curve)
	}
	return buf.Bytes()
}

func (e *ExtSupportedGroups) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &e.Length)
	e.NamedCurve = make([]NamedCurve, 0)
	read := 0
	for read < int(e.Length) {
		var curve NamedCurve
		_ = binary.Read(buf, binary.BigEndian, &curve)
		e.NamedCurve = append(e.NamedCurve, curve)
		read += 2
	}
	return len(data) - buf.Len()
}

// Extension: Signature algorithms
type ExtSignatureAlgorithms struct {
	Length              uint16
	SignatureAlgorithms []SignatureAlgorithms
}

func (e *ExtSignatureAlgorithms) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, e.Length)
	for _, algorithm := range e.SignatureAlgorithms {
		_ = binary.Write(buf, binary.BigEndian, algorithm)
	}
	return buf.Bytes()
}

func (e *ExtSignatureAlgorithms) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &e.Length)
	e.SignatureAlgorithms = make([]SignatureAlgorithms, 0)
	read := 0
	for read < int(e.Length) {
		var algorithm SignatureAlgorithms
		_ = binary.Read(buf, binary.BigEndian, &algorithm)
		e.SignatureAlgorithms = append(e.SignatureAlgorithms, algorithm)
		read += 2
	}
	return len(data) - buf.Len()
}

// Extension: Key share
type ExtKeyShare struct {
	Length      uint16
	Group       NamedCurve
	KeyLength   uint16
	KeyExchange []byte
}

func (e *ExtKeyShare) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, e.Length)
	_ = binary.Write(buf, binary.BigEndian, e.Group)
	_ = binary.Write(buf, binary.BigEndian, e.KeyLength)
	buf.Write(e.KeyExchange)
	return buf.Bytes()
}

func (e *ExtKeyShare) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &e.Length)
	_ = binary.Read(buf, binary.BigEndian, &e.Group)
	_ = binary.Read(buf, binary.BigEndian, &e.KeyLength)
	e.KeyExchange = make([]byte, e.KeyLength)
	copy(e.KeyExchange, buf.Next(int(e.KeyLength)))
	return len(data) - buf.Len()
}

// Extension: PSK key exchange mode
type ExtPSKKeyExchangeModes struct {
	Length              uint8
	PSKKeyExchangeModes []PSKKeyExchangeMode
}

func (e *ExtPSKKeyExchangeModes) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, e.Length)
	for _, pskMode := range e.PSKKeyExchangeModes {
		_ = binary.Write(buf, binary.BigEndian, pskMode)
	}
	return buf.Bytes()
}

func (e *ExtPSKKeyExchangeModes) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &e.Length)
	e.PSKKeyExchangeModes = make([]PSKKeyExchangeMode, 0)
	read := 0
	for read < int(e.Length) {
		var pskMode PSKKeyExchangeMode
		_ = binary.Read(buf, binary.BigEndian, &pskMode)
		e.PSKKeyExchangeModes = append(e.PSKKeyExchangeModes, pskMode)
		read += 1
	}
	return len(data) - buf.Len()
}

// Extension: Supported version
type ExtSupportedVersions struct {
	Length            uint8
	SupportedVersions []ProtocolVersion
}

func (e *ExtSupportedVersions) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, e.Length)
	for _, protocolVersion := range e.SupportedVersions {
		_ = binary.Write(buf, binary.BigEndian, protocolVersion)
	}
	return buf.Bytes()
}

func (e *ExtSupportedVersions) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &e.Length)
	e.SupportedVersions = make([]ProtocolVersion, 0)
	read := 0
	for read < int(e.Length) {
		var protocolVersion ProtocolVersion
		_ = binary.Read(buf, binary.BigEndian, &protocolVersion)
		e.SupportedVersions = append(e.SupportedVersions, protocolVersion)
		read += 2
	}
	return len(data) - buf.Len()
}
