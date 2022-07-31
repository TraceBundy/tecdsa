package curve

import (
	"encoding/hex"
	"github.com/magiconair/properties/assert"
	"testing"
)

func toString(s EccFieldElement) string {
	return "0x" + hex.EncodeToString(s.AsBytes())
}
func TestSecp256k1(t *testing.T) {
	assert.Equal(t, toString(Field.Zero(K256)), "0x0000000000000000000000000000000000000000000000000000000000000000")
	assert.Equal(t, toString(Field.One(K256)), "0x0000000000000000000000000000000000000000000000000000000000000001")
	assert.Equal(t, toString(Field.A(K256)), "0x0000000000000000000000000000000000000000000000000000000000000000")
	assert.Equal(t, toString(Field.B(K256)), "0x0000000000000000000000000000000000000000000000000000000000000007")
	assert.Equal(t, toString(Field.SswuC2(K256)), "0x31fdf302724013e57ad13fb38f842afeec184f00a74789dd286729c8303c4a59")
	assert.Equal(t, toString(Field.SswuZ(K256)), "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc24")
	assert.Equal(t, toString(Field.SswuA(K256)), "0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533")
	assert.Equal(t, toString(Field.SswuB(K256)), "0x00000000000000000000000000000000000000000000000000000000000006eb")

	a := Field.SswuA(K256).Invert(Field.SswuA(K256))
	assert.Equal(t, toString(a), "0x2cf2e1012a9416f39cbf60f32404a38ff743ccf943a9d2667cf0d2335940bc82")
	a = Field.SswuA(K256).Negate(Field.SswuA(K256))
	assert.Equal(t, toString(a), "0xc078ce542299e5235f75aaa70f0a2d8d16ac2c9c3490f1a2bfabb83ee5bbb6fc")
	a, _ = Field.SswuA(K256).Sqrt(Field.SswuA(K256))
	assert.Equal(t, toString(a), "0x0000000000000000000000000000000000000000000000000000000000000000")
	//a = Field.SswuA(K256).Progenitor(Field.SswuA(K256))
	//assert.Equal(t, toString(a), "0x5a839b0f169007abed6a6312e3fffed8db39a7678938f006afc3b389f61d71de")
}
