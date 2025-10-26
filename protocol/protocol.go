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

type ExchangeObject interface {
	Serialize() []byte
	Deserialize([]byte) int
}

type Record struct {
	Type            RecordContentType
	ProtocolVersion ProtocolVersion
	Length          uint16
	Fragment        ExchangeObject
}

func NewRecord(recordType RecordContentType, protocolVersion ProtocolVersion, fragment ExchangeObject) *Record {
	return &Record{
		Type:            recordType,
		ProtocolVersion: protocolVersion,
		Fragment:        fragment,
	}
}

func (r *Record) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, r.Type)
	_ = binary.Write(buf, binary.BigEndian, r.ProtocolVersion)

	fragment := r.Fragment.Serialize()
	_ = binary.Write(buf, binary.BigEndian, uint16(len(fragment)))
	buf.Write(fragment)

	return buf.Bytes()
}

func (r *Record) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &r.Type)
	_ = binary.Read(buf, binary.BigEndian, &r.ProtocolVersion)
	_ = binary.Read(buf, binary.BigEndian, &r.Length)
	r.Fragment = newFragment(r.Type)
	r.Fragment.Deserialize(buf.Next(int(r.Length)))
	return len(data) - buf.Len()
}

func newFragment(recordContentType RecordContentType) ExchangeObject {
	switch recordContentType {
	case Record_Handshake:
		return &HandShake{}
	}
	return nil
}
