package sessionstate

import "encoding/binary"

type Nonce struct {
	n     uint64
	bytes []byte
}

// NewNonce creates a new Nonce with the specified size
func NewNonce(size int) *Nonce {
	n := &Nonce{
		n:     0,
		bytes: make([]byte, size),
	}
	// Even though we're treating the nonce as 8 bytes, RFC7539 specifies 12 bytes for a nonce.
	binary.LittleEndian.PutUint64(n.bytes[size-8:], n.n)
	return n
}

func (n *Nonce) Increment() {
	n.n++
	binary.LittleEndian.PutUint64(n.bytes[len(n.bytes)-8:], n.n)
}

// GetBytes returns the byte representation of the nonce
func (n *Nonce) GetBytes() []byte {
	return n.bytes
}

// GetUint64 returns the counter value as uint64
func (n *Nonce) GetUint64() uint64 {
	return n.n
}
