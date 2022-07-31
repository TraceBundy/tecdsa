package seed

import (
	"crypto/sha256"
	"github.com/pkg/errors"
)

const (
	maxLen = 255 * 32
)

func ExpandMessageXmd(msg []byte, domainSeparator []byte, length int) ([]byte, error) {
	if length > maxLen {
		return nil, errors.Errorf("Requested XMD output length %d too large (max: %d)", length, maxLen)
	}
	ell := (length-1)/32 + 1

	xmd := func(dst []byte) []byte {
		out := make([]byte, 0, ell*32)
		empty := [64]byte{}
		state := sha256.New()
		state.Write(empty[:])
		state.Write(msg)
		state.Write([]byte{byte(length / 256), byte(length % 256), 0})
		state.Write(dst)
		state.Write([]byte{byte(len(dst))})
		b0 := state.Sum(nil)
		state.Reset()
		state.Write(b0)
		state.Write([]byte{byte(1)})
		state.Write(dst)
		state.Write([]byte{byte(len(dst))})
		out = append(out, state.Sum(nil)...)

		for i := 2; i <= ell; i++ {
			var tmp [32]byte
			for j := 0; j < 32; j++ {
				tmp[j] = b0[j] ^ out[len(out)-32+j]
			}
			state.Reset()
			state.Write(tmp[:])
			state.Write([]byte{byte(i)})
			state.Write(dst)
			state.Write([]byte{byte(len(dst))})
			out = append(out, state.Sum(nil)...)
		}
		return out

	}
	var out []byte
	if len(domainSeparator) >= 256 {
		state := sha256.New()
		state.Write([]byte("H2C-OVERSIZE-DST-"))
		state.Write(domainSeparator)
		out = xmd(state.Sum(nil))
	} else {
		out = xmd(domainSeparator)
	}
	if len(out) > length {
		out = out[:length]
	}
	return out, nil
}
