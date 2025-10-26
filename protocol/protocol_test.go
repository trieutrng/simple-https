package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestBuffer(t *testing.T) {
	data := []byte("hello world ! ")
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, []byte("Trieu "))
	buf.Write(data)

	str := fmt.Sprintf("%s", buf.Bytes())

	if str != "Trieu hello world ! " {
		t.Errorf("str: %s", str)
	}
}
