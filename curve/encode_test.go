package curve

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

/// Identity point
var (
	IdentityBytes        = []byte{0}
	UncompressedBytes, _ = hex.DecodeString("0411111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222")
	CompressedBytes, _   = hex.DecodeString("021111111111111111111111111111111111111111111111111111111111111111")
)

func TestDecodeCompressedPoint(t *testing.T) {
	compressedEventYBytes, _ := hex.DecodeString("020100000000000000000000000000000000000000000000000000000000000000")
	compressedEvenY, err := Encode.FromBytes(compressedEventYBytes)
	assert.Nil(t, err)
	assert.True(t, compressedEvenY.IsCompressed())
	assert.Equal(t, CompressedEvenY, compressedEvenY.Tag())
	assert.Equal(t, 33, compressedEvenY.Len())
	assert.Equal(t, compressedEventYBytes, compressedEvenY.AsBytes())
	x, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	assert.Equal(t, &CompressedCoordinates{
		x:      x,
		yIsOdd: false,
	}, compressedEvenY.Coordinates())
	assert.Equal(t, x, compressedEvenY.X())
	assert.Equal(t, []byte(nil), compressedEvenY.Y())

	compressedOddYBytes, _ := hex.DecodeString("030200000000000000000000000000000000000000000000000000000000000000")
	compressedOddY, err := Encode.FromBytes(compressedOddYBytes)
	assert.Nil(t, err)
	assert.True(t, compressedOddY.IsCompressed())
	assert.Equal(t, CompressedOddY, compressedOddY.Tag())
	assert.Equal(t, 33, compressedOddY.Len())
	assert.Equal(t, compressedOddYBytes, compressedOddY.AsBytes())
	x, _ = hex.DecodeString("0200000000000000000000000000000000000000000000000000000000000000")
	assert.Equal(t, &CompressedCoordinates{
		x:      x,
		yIsOdd: true,
	}, compressedOddY.Coordinates())

	assert.Equal(t, x, compressedOddY.X())
	assert.Equal(t, []byte(nil), compressedOddY.Y())
}

func TestDecodeUncompressedPoint(t *testing.T) {
	uncompressedPoint, err := Encode.FromBytes(UncompressedBytes)
	assert.Nil(t, err)
	assert.False(t, uncompressedPoint.IsCompressed())
	assert.Equal(t, Uncompressed, uncompressedPoint.Tag())
	assert.Equal(t, 65, uncompressedPoint.Len())
	assert.Equal(t, UncompressedBytes, uncompressedPoint.AsBytes())
	x, _ := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	y, _ := hex.DecodeString("2222222222222222222222222222222222222222222222222222222222222222")
	assert.Equal(t, &UnCompressedCoordinates{
		x: x,
		y: y,
	}, uncompressedPoint.Coordinates())

	assert.Equal(t, x, uncompressedPoint.X())
	assert.Equal(t, y, uncompressedPoint.Y())
}

func TestDecodeIdentity(t *testing.T) {
	identityPoint, _ := Encode.FromBytes(IdentityBytes)
	assert.True(t, identityPoint.IsIdentity())
	assert.Equal(t, Identity, identityPoint.Tag())
	assert.Equal(t, 1, identityPoint.Len())
	assert.Equal(t, IdentityBytes, identityPoint.AsBytes())
	assert.Equal(t, IdentityCoordinates{}, identityPoint.Coordinates())
	assert.Equal(t, []byte(nil), identityPoint.X())
	assert.Equal(t, []byte(nil), identityPoint.Y())
}

func TestDecodeInvalidTag(t *testing.T) {

	compressedBytes := make([]byte, len(CompressedBytes), len(CompressedBytes))
	copy(compressedBytes, CompressedBytes)
	uncompressedBytes := make([]byte, len(UncompressedBytes), len(UncompressedBytes))
	copy(uncompressedBytes, uncompressedBytes)
	for _, bytes := range [][]byte{compressedBytes, uncompressedBytes} {
		for tag := byte(0); tag <= byte(254); tag++ {
			if tag == byte(2) || tag == byte(3) || tag == byte(4) || tag == 5 {
				continue
			}
			bytes[0] = tag
			_, err := Encode.FromBytes(bytes)
			assert.NotNil(t, err)
		}
	}
}

func TestDecodeTruncatedPoint(t *testing.T) {
	for _, bytes := range [][]byte{CompressedBytes, UncompressedBytes} {
		for i := 1; i < len(bytes); i++ {
			_, err := Encode.FromBytes(bytes[0:i])
			assert.NotNil(t, err)
		}
	}
}

func TestFromUntaggedPoint(t *testing.T) {
	untaggedBytes, _ := hex.DecodeString("11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222")
	uncompressedPoint := Encode.FromUnTaggedBytes(untaggedBytes)
	assert.Equal(t, UncompressedBytes, uncompressedPoint.AsBytes())
}

func TestFromAffineCoordinates(t *testing.T) {
	x, _ := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	y, _ := hex.DecodeString("2222222222222222222222222222222222222222222222222222222222222222")
	uncompressedPoint := Encode.FromAffineCoordinates(x, y, false)
	assert.Equal(t, UncompressedBytes, uncompressedPoint.AsBytes())
	compressedPoint := Encode.FromAffineCoordinates(x, y, true)
	assert.Equal(t, CompressedBytes, compressedPoint.AsBytes())
}

func TestCompress(t *testing.T) {
	uncompressedPoint, err := Encode.FromBytes(UncompressedBytes)
	assert.Nil(t, err)
	compressedPoint := uncompressedPoint.Compress()
	assert.Equal(t, compressedPoint.AsBytes(), CompressedBytes)
}

func TestConditionalSelect(t *testing.T) {
	a, err := Encode.FromBytes(CompressedBytes)
	assert.Nil(t, err)
	b, err := Encode.FromBytes(UncompressedBytes)
	assert.Nil(t, err)
	as := Encode.ConditionalSelect(a, b, 0)
	assert.Equal(t, a, as)
	bs := Encode.ConditionalSelect(a, b, 1)
	assert.Equal(t, b, bs)
}

func TestIdentity(t *testing.T) {
	identityPoint := Encode.Identity()
	assert.Equal(t, Identity, identityPoint.Tag())
	assert.Equal(t, 1, identityPoint.Len())
	assert.Equal(t, IdentityBytes, identityPoint.AsBytes())
	assert.Equal(t, Encode.Default(), identityPoint)
}

func TestDecodeHex(t *testing.T) {
	point, err := Encode.FromStr("021111111111111111111111111111111111111111111111111111111111111111")
	assert.Nil(t, err)
	assert.Equal(t, CompressedBytes, point.AsBytes())
}

func TestToBytes(t *testing.T) {
	uncompressedPoint, err := Encode.FromBytes(UncompressedBytes)
	assert.Nil(t, err)
	assert.Equal(t, UncompressedBytes, uncompressedPoint.AsBytes())
}

func TestToString(t *testing.T) {
	compressedPoint, err := Encode.FromBytes(CompressedBytes)
	assert.Nil(t, err)
	assert.Equal(t, "021111111111111111111111111111111111111111111111111111111111111111", compressedPoint.ToString())
}
