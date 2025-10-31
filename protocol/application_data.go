package protocol

import (
	"bytes"
	"encoding/binary"

	"trieutrng.com/toy-tls/common"
)

type ApplicationData struct {
	Content []byte
}

func (a *ApplicationData) Serialize() []byte {
	buf := new(bytes.Buffer)
	buf.Write(a.Content)
	return buf.Bytes()
}

func (a *ApplicationData) Deserialize(data []byte) int {
	a.Content = make([]byte, len(data))
	copy(a.Content, data)
	return len(data)
}

type DecryptedApplicationData struct {
	Content     common.ExchangeObject
	ContentType ContentType
}

func (d *DecryptedApplicationData) Serialize() []byte {
	buf := new(bytes.Buffer)
	buf.Write(d.Content.Serialize())
	_ = binary.Write(buf, binary.BigEndian, d.ContentType)
	return buf.Bytes()
}

func (d *DecryptedApplicationData) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	read := d.Content.Deserialize(data)
	buf.Next(read)
	_ = binary.Read(buf, binary.BigEndian, &d.ContentType)
	return len(data) - buf.Len()
}
