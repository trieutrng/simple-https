package helpers

import "encoding/binary"

func MarshalUint24(n int) []byte {
	return []byte{byte(n >> 16), byte(n >> 8), byte(n)}
}

func UnmarshalUint24(b []byte) int {
	if len(b) < 3 {
		return 0
	}
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

func Uint16ToBytes(n uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return b
}
