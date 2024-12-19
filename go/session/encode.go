package session

import "encoding/binary"

// encodeUint32 converts a uint32 to a byte slice in little-endian format
func encodeUint32(n int32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(n))
	return buf
}
