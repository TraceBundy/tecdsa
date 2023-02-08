package curve

import (
	"encoding/hex"
	"github.com/TraceBundy/tecdsa/seed"
	"github.com/stretchr/testify/assert"
	"testing"
)

func xmdCheck(t *testing.T, msg, dst, want string) {
	x, err := seed.ExpandMessageXmd([]byte(msg), []byte(dst), len(want)/2)
	assert.Nil(t, err)
	assert.Equal(t, want, hex.EncodeToString(x))
}

func TestExpandMessageXmd(t *testing.T) {
	x, err := seed.ExpandMessageXmd([]byte("foo"), []byte("bar"), 123)
	assert.Nil(t, err)
	assert.Equal(t, 123, len(x))
	xmdCheck(t, "",
		"QUUX-V01-CS02-with-expander-SHA256-128",
		"68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235")
	xmdCheck(t, "abc",
		"QUUX-V01-CS02-with-expander-SHA256-128",
		"d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615")
	xmdCheck(t, "", "QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		"e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3")
	xmdCheck(t, "abc", "QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		"52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12")
}

func TestHash2CurveKatK256(t *testing.T) {
	curve := K256
	dst := []byte("QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_")
	tests := [][3]string{
		{"", "c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346", "64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067"},
		{"abc", "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b", "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6"},
		{"abcdef0123456789", "bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a", "4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828"},
	}
	for _, c := range tests {
		input, x, y := []byte(c[0]), c[1], c[2]
		pt, err := Point.HashToPoint(curve, input, dst)
		assert.Nil(t, err)
		assert.Equal(t, hex.EncodeToString(pt.AffineX().AsBytes()), x)
		assert.Equal(t, hex.EncodeToString(pt.AffineY().AsBytes()), y)

	}
}
