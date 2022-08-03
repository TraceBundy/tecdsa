package ro

import (
	"encoding/hex"
	"github.com/PlatONnetwork/tecdsa/curve"
	seed2 "github.com/PlatONnetwork/tecdsa/seed"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRandomOracleStability(t *testing.T) {
	curveType := curve.K256
	var bytes [32]byte
	for i := range bytes {
		bytes[i] = 0x42
	}
	seed := seed2.FromBytes(bytes[:])
	rng := seed.Rng()

	ro := NewRandomOracle("ic-test-domain-sep")
	s1 := curve.Scalar.Random(curveType, rng)
	pt1 := curve.Point.GeneratorG(curveType).ScalarMul(curve.Point.GeneratorG(curveType), s1)
	ro.AddPoint("pt1", pt1)
	assert.NotNil(t, ro.AddPoint("pt1", pt1))
	var b42 [42]byte
	for i := range b42 {
		b42[i] = 42
	}
	ro.AddUint64("i1", 42)
	ro.AddBytesString("v1", b42[:])
	ro.AddScalar("s1", s1)
	ro.AddUint64("round", 1)
	c1, err := ro.OutputScalars(curveType, 2)
	assert.Nil(t, err)
	assert.Equal(t, "e1cc3546518665d7321cd5b5aa7cbae2ae9d8bad3a2f28b495ac3d3af139b460", hex.EncodeToString(c1[0].Serialize()))
	assert.Equal(t, "d46b5ef6fafdaf2a1e50f7b979f1fd31e058e9c2ab69115c4f2c15077ae94969", hex.EncodeToString(c1[1].Serialize()))
	ro = NewRandomOracle("ic-test-domain-sep-2")
	ro.AddScalar("c1", c1[1])
	ro.AddUint64("round", 2)
	c2, err := ro.OutputScalar(curveType)
	assert.Nil(t, err)
	assert.Equal(t, "f35e7f0a649f8c8e92084d04d40cd13cb82e9e2ebc3aabb5bd88c04ce2f5ebe9", hex.EncodeToString(c2.Serialize()))

	ro = NewRandomOracle("ic-test-domain-sep-3")
	ro.AddScalar("c2", c2)
	ro.AddUint64("round", 3)
	byteOutput, err := ro.OutputByteString(42)
	assert.Nil(t, err)
	assert.Equal(t, "c569bf3e900df5d5e61fdf3b9d798d3089bf9dfd875e8735cb99aef2e5a865f2eb44fb6f363730a4b2dc", hex.EncodeToString(byteOutput))
}
