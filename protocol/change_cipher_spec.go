package protocol

import (
	"bytes"
	"encoding/binary"
)

type ChangeCipherSpec struct {
	Payload byte
}

func NewChangeCipherSpec(payload byte) *ChangeCipherSpec {
	return &ChangeCipherSpec{
		Payload: payload,
	}
}

func (c *ChangeCipherSpec) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, c.Payload)
	return buf.Bytes()
}

func (c *ChangeCipherSpec) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &c.Payload)
	return len(data) - buf.Len()
}
