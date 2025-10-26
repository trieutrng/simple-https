package helpers

import "encoding/binary"

func u16(val uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, val)
	return buf
}
