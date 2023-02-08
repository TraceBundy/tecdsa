package seed

import (
	"crypto/cipher"
	"github.com/TraceBundy/tecdsa/rand"
	"go.dedis.ch/kyber/v3/util/random"
)

const seedLen = 32

type Seed struct {
	value [seedLen]byte
}

func NewSeed(input []byte, domainSeparator string) *Seed {
	derived, err := ExpandMessageXmd(input, []byte(domainSeparator), seedLen)
	if err != nil {
		panic(err.Error())
	}
	seed := &Seed{}
	copy(seed.value[:], derived)
	return seed
}

func FromBytes(value []byte) *Seed {
	return NewSeed(value, "ic-crypto-seed-from-bytes")
}

func FromRandomness(r cipher.Stream) *Seed {
	var value [seedLen]byte
	random.Bytes(value[:], r)
	return NewSeed(value[:], "ic-crypto-seed-from-randomness")
}

func FromRng(r rand.Rand) *Seed {
	var o [seedLen]byte
	r.FillUint8(o[:])
	return NewSeed(o[:], "ic-crypto-seed-from-rng")
}

func (s Seed) Derive(domainSeparator string) *Seed {
	return NewSeed(s.value[:], domainSeparator)
}

func (s Seed) Rng() rand.Rand {
	return rand.NewChaCha20(s.value[:])
}
