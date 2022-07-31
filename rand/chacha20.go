package rand

import (
	"encoding/binary"
	"golang.org/x/crypto/chacha20"
)

type ChaCha20 struct {
	cipher *chacha20.Cipher
}

func NewChaCha20(seed []byte) *ChaCha20 {
	var nonce [12]byte
	c, err := chacha20.NewUnauthenticatedCipher(seed, nonce[:])
	if err != nil {
		panic(err.Error())
	}
	return &ChaCha20{
		cipher: c,
	}
}

func (c ChaCha20) Uint32() uint32 {
	var res [4]byte
	c.cipher.XORKeyStream(res[:], res[:])
	return binary.BigEndian.Uint32(res[:])
}

func (c ChaCha20) Uint64() uint64 {
	var res [8]byte
	c.cipher.XORKeyStream(res[:], res[:])
	return binary.BigEndian.Uint64(res[:])
}

func (c *ChaCha20) FillUint8(res []uint8) {
	c.cipher.XORKeyStream(res, res)
}

func (c *ChaCha20) XORKeyStream(dst, src []byte) {
	c.cipher.XORKeyStream(dst, src)
}
