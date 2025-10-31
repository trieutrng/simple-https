package protocol

import (
	"bytes"
	"encoding/binary"

	"trieutrng.com/toy-tls/common"
)

const RecordHeaderLen int = 5

type ContentType uint8

const (
	Record_Invalid          ContentType = 0x00
	Record_ChangeCipherSpec ContentType = 0x14
	Record_Alert            ContentType = 0x15
	Record_Handshake        ContentType = 0x16
	Record_ApplicationData  ContentType = 0x17
	Record_Heartbeat        ContentType = 0x18
)

type Record struct {
	Type            ContentType
	ProtocolVersion common.ProtocolVersion
	Length          uint16
	Fragment        common.ExchangeObject
}

func NewRecord(recordType ContentType, protocolVersion common.ProtocolVersion, fragment common.ExchangeObject) *Record {
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
	r.Fragment = NewFragment(r.Type)
	r.Fragment.Deserialize(buf.Next(int(r.Length)))
	return len(data) - buf.Len()
}

func NewFragment(recordContentType ContentType) common.ExchangeObject {
	switch recordContentType {
	case Record_Handshake:
		return &HandShake{}
	case Record_ChangeCipherSpec:
		return &ChangeCipherSpec{}
	case Record_ApplicationData:
		return &ApplicationData{}
	case Record_Alert:
		return &Alert{}
	}
	return nil
}
