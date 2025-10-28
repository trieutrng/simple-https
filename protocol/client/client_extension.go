package client

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"trieutrng.com/toy-tls/common"
)

type Extensions struct {
	Length uint16
	Data   []Extension
}

func NewExtensions(extensions []Extension) *Extensions {
	return &Extensions{
		Data: extensions,
	}
}

func (e *Extensions) Serialize() []byte {
	buf := new(bytes.Buffer)

	dataBuf := new(bytes.Buffer)
	for _, extension := range e.Data {
		_ = binary.Write(dataBuf, binary.BigEndian, extension.Serialize())
	}
	extensions := dataBuf.Bytes()
	_ = binary.Write(buf, binary.BigEndian, uint16(len(extensions)))
	buf.Write(extensions)

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
	Type   common.ExtensionType
	Length uint16
	Data   common.ExchangeObject
}

func NewExtension(extType common.ExtensionType, data common.ExchangeObject) *Extension {
	return &Extension{
		Type: extType,
		Data: data,
	}
}

func (e *Extension) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, e.Type)

	dataBuf := e.Data.Serialize()
	_ = binary.Write(buf, binary.BigEndian, uint16(len(dataBuf)))
	buf.Write(dataBuf)

	return buf.Bytes()
}

func (e *Extension) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &e.Type)
	_ = binary.Read(buf, binary.BigEndian, &e.Length)
	e.Data = newExtension(e.Type)
	e.Data.Deserialize(buf.Next(int(e.Length)))
	return len(data) - buf.Len()
}

func newExtension(extType common.ExtensionType) common.ExchangeObject {
	switch extType {
	case common.Ext_ServerName:
		return &ExtServerNameList{}
	case common.Ext_SupportedGroups:
		return &ExtSupportedGroups{}
	case common.Ext_SignatureAlgorithms:
		return &ExtSignatureAlgorithms{}
	case common.Ext_KeyShare:
		return &ExtKeyShare{}
	case common.Ext_PSKKeyExchangeModes:
		return &ExtPSKKeyExchangeModes{}
	case common.Ext_SupportedVersions:
		return &ExtSupportedVersions{}
	}
	return nil
}

type ExtServerNameList struct {
	Length     uint16
	ServerName ServerName
}

func NewExtServerNameList(serverName *ServerName) *ExtServerNameList {
	return &ExtServerNameList{
		ServerName: *serverName,
	}
}

func (e *ExtServerNameList) Serialize() []byte {
	buf := new(bytes.Buffer)
	serverNameBuf := e.ServerName.Serialize()
	_ = binary.Write(buf, binary.BigEndian, uint16(len(serverNameBuf)))
	buf.Write(serverNameBuf)
	return buf.Bytes()
}

func (e *ExtServerNameList) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &e.Length)
	e.ServerName = ServerName{}
	e.ServerName.Deserialize(buf.Next(int(e.Length)))
	return len(data) - buf.Len()
}

func (e *ExtServerNameList) String() string {
	return fmt.Sprintf("Server name list: \n\t%s", e.ServerName.String())
}

type ServerName struct {
	NameType common.ServerNameType
	Length   uint16
	Data     []byte
}

func NewServerName(nameType common.ServerNameType, name []byte) *ServerName {
	return &ServerName{
		NameType: nameType,
		Data:     name,
	}
}

func (s *ServerName) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, s.NameType)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(s.Data)))
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

func (s *ServerName) String() string {
	return fmt.Sprintf("Server name: %s", string(s.Data))
}

type ExtSupportedGroups struct {
	Length     uint16
	NamedCurve []common.NamedCurve
}

func NewExtSupportedGroups(namedCurve []common.NamedCurve) *ExtSupportedGroups {
	return &ExtSupportedGroups{
		NamedCurve: namedCurve,
	}
}

func (e *ExtSupportedGroups) Serialize() []byte {
	buf := new(bytes.Buffer)

	namedCurveBuf := new(bytes.Buffer)
	for _, namedCurve := range e.NamedCurve {
		_ = binary.Write(namedCurveBuf, binary.BigEndian, namedCurve)
	}
	namedCurves := namedCurveBuf.Bytes()
	_ = binary.Write(buf, binary.BigEndian, uint16(len(namedCurves)))
	buf.Write(namedCurves)

	return buf.Bytes()
}

func (e *ExtSupportedGroups) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &e.Length)
	e.NamedCurve = make([]common.NamedCurve, 0)
	read := 0
	for read < int(e.Length) {
		var curve common.NamedCurve
		_ = binary.Read(buf, binary.BigEndian, &curve)
		e.NamedCurve = append(e.NamedCurve, curve)
		read += 2
	}
	return len(data) - buf.Len()
}

func (e *ExtSupportedGroups) String() string {
	return fmt.Sprintf("Supported groups: %v", e.NamedCurve)
}

type ExtSignatureAlgorithms struct {
	Length              uint16
	SignatureAlgorithms []common.SignatureAlgorithms
}

func NewExtSignatureAlgorithms(signatureAlgorithms []common.SignatureAlgorithms) *ExtSignatureAlgorithms {
	return &ExtSignatureAlgorithms{
		SignatureAlgorithms: signatureAlgorithms,
	}
}

func (e *ExtSignatureAlgorithms) Serialize() []byte {
	buf := new(bytes.Buffer)

	signatureAlgorithmsBuf := new(bytes.Buffer)
	for _, signatureAlgorithm := range e.SignatureAlgorithms {
		_ = binary.Write(signatureAlgorithmsBuf, binary.BigEndian, signatureAlgorithm)
	}
	signatureAlgorithms := signatureAlgorithmsBuf.Bytes()
	_ = binary.Write(buf, binary.BigEndian, uint16(len(signatureAlgorithms)))
	buf.Write(signatureAlgorithms)

	return buf.Bytes()
}

func (e *ExtSignatureAlgorithms) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &e.Length)
	e.SignatureAlgorithms = make([]common.SignatureAlgorithms, 0)
	read := 0
	for read < int(e.Length) {
		var algorithm common.SignatureAlgorithms
		_ = binary.Read(buf, binary.BigEndian, &algorithm)
		e.SignatureAlgorithms = append(e.SignatureAlgorithms, algorithm)
		read += 2
	}
	return len(data) - buf.Len()
}

func (e *ExtSignatureAlgorithms) String() string {
	return fmt.Sprintf("Signature algorithms: %v", e.SignatureAlgorithms)
}

type ExtKeyShare struct {
	Length      uint16
	Group       common.NamedCurve
	KeyLength   uint16
	KeyExchange []byte
}

func NewExtKeyShare(group common.NamedCurve, key []byte) *ExtKeyShare {
	return &ExtKeyShare{
		Group:       group,
		KeyExchange: key,
	}
}

func (e *ExtKeyShare) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, uint16(2+2+len(e.KeyExchange))) // 2 bytes group + 2 bytes key length + key length
	_ = binary.Write(buf, binary.BigEndian, e.Group)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(e.KeyExchange)))
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

func (e *ExtKeyShare) String() string {
	return fmt.Sprintf("Key share: \n\t\tgroup: %v \n\t\tkey: %v", e.Group, e.KeyExchange[:e.KeyLength])
}

type ExtPSKKeyExchangeModes struct {
	Length              uint8
	PSKKeyExchangeModes []common.PSKKeyExchangeMode
}

func NewExtPSKKeyExchangeModes(pskKeyExchangeModes []common.PSKKeyExchangeMode) *ExtPSKKeyExchangeModes {
	return &ExtPSKKeyExchangeModes{
		PSKKeyExchangeModes: pskKeyExchangeModes,
	}
}

func (e *ExtPSKKeyExchangeModes) Serialize() []byte {
	buf := new(bytes.Buffer)

	pskKeyExchangeModesBuf := new(bytes.Buffer)
	for _, pskKeyExchangeMode := range e.PSKKeyExchangeModes {
		_ = binary.Write(pskKeyExchangeModesBuf, binary.BigEndian, pskKeyExchangeMode)
	}
	pskKeyExchangeModes := pskKeyExchangeModesBuf.Bytes()
	_ = binary.Write(buf, binary.BigEndian, uint8(len(pskKeyExchangeModes)))
	buf.Write(pskKeyExchangeModes)

	return buf.Bytes()
}

func (e *ExtPSKKeyExchangeModes) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &e.Length)
	e.PSKKeyExchangeModes = make([]common.PSKKeyExchangeMode, 0)
	read := 0
	for read < int(e.Length) {
		var pskMode common.PSKKeyExchangeMode
		_ = binary.Read(buf, binary.BigEndian, &pskMode)
		e.PSKKeyExchangeModes = append(e.PSKKeyExchangeModes, pskMode)
		read += 1
	}
	return len(data) - buf.Len()
}

func (e *ExtPSKKeyExchangeModes) String() string {
	return fmt.Sprintf("PSK Key Exchange Modes: %v", e.PSKKeyExchangeModes)
}

type ExtSupportedVersions struct {
	Length            uint8
	SupportedVersions []common.ProtocolVersion
}

func NewExtSupportedVersions(versions []common.ProtocolVersion) *ExtSupportedVersions {
	return &ExtSupportedVersions{
		SupportedVersions: versions,
	}
}

func (e *ExtSupportedVersions) Serialize() []byte {
	buf := new(bytes.Buffer)

	versionsBuf := new(bytes.Buffer)
	for _, version := range e.SupportedVersions {
		_ = binary.Write(versionsBuf, binary.BigEndian, version)
	}
	supportedVersions := versionsBuf.Bytes()
	_ = binary.Write(buf, binary.BigEndian, uint8(len(supportedVersions)))
	buf.Write(supportedVersions)

	return buf.Bytes()
}

func (e *ExtSupportedVersions) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &e.Length)
	e.SupportedVersions = make([]common.ProtocolVersion, 0)
	read := 0
	for read < int(e.Length) {
		var protocolVersion common.ProtocolVersion
		_ = binary.Read(buf, binary.BigEndian, &protocolVersion)
		e.SupportedVersions = append(e.SupportedVersions, protocolVersion)
		read += 2
	}
	return len(data) - buf.Len()
}

func (e *ExtSupportedVersions) String() string {
	return fmt.Sprintf("Supported Versions: %v", e.SupportedVersions)
}
