package curve

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNotAffectedByPointSerializationBug(t *testing.T) {
	curve := K256
	pts := []string{
		"024b395881d9965c4621459ad2ec12716fa7f669b6108ad3b8b82b91644fb44808",
		"02e77d7b458fb3a2df7d201806e8e1dbce8c1138303156c43398ac62891c43e3cc",
		"02f973e12be0ea160cc82c16563753749b5e6590d22a0b9ab16cd48b9bd951b167",
	}
	for _, pt := range pts {
		bytes, _ := hex.DecodeString(pt)
		pt, err := Point.Deserialize(curve, bytes)
		assert.Nil(t, err)
		ptBytes := pt.Serialize()
		assert.Equal(t, bytes, ptBytes)
	}
}

func TestVerifySerializationRoundTripsCorrectly(t *testing.T) {
	assertSerializationRoundTrips := func(pt EccPoint) {
		curve := pt.CurveType()
		b := pt.Serialize()
		assert.Equal(t, curve.PointBytes(), len(b))
		pt2, err := Point.Deserialize(curve, b)
		assert.Nil(t, err)
		assert.Equal(t, 1, pt.Equal(pt2))
		b2 := pt2.Serialize()
		assert.Equal(t, b, b2)
	}
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curve := range all() {
		identity := Point.Identity(curve)
		for _, x := range identity.Serialize() {
			assert.Equal(t, x, uint8(0x00))
		}
		assertSerializationRoundTrips(identity)
		assertSerializationRoundTrips(Point.GeneratorG(curve))
		assertSerializationRoundTrips(Point.GeneratorH(curve))
		for r := 0; r < 100; r++ {
			s := Scalar.Random(curve, rng)
			gs := Point.MulByG(s)
			assertSerializationRoundTrips(gs)
		}
	}
}

func TestHashToScalarIsDeterministic(t *testing.T) {
	input := []byte("test input string")
	domainSeparator := []byte("domain sep")
	for _, curve := range all() {
		s1, err := Scalar.HashToScalar(curve, input, domainSeparator)
		assert.Nil(t, err)
		s2, err := Scalar.HashToScalar(curve, input, domainSeparator)
		assert.Nil(t, err)
		assert.Equal(t, hex.EncodeToString(s1.Serialize()), hex.EncodeToString(s2.Serialize()))
	}
}

func TestHashToScalarK256HasFixedOutput(t *testing.T) {
	curve := K256
	input := []byte("known answer test input")
	domainSeparator := []byte("domain sep")
	s, err := Scalar.HashToScalar(curve, input, domainSeparator)

	assert.Nil(t, err)
	assert.Equal(t, hex.EncodeToString(s.Serialize()), "3670f931a6cbff777594bf1488812b63895dfe5df9814584dfd231f69a66541a")
}

func TestGeneratorHHasExpectedValue(t *testing.T) {
	for _, curve := range all() {
		h := Point.GeneratorH(curve)
		input := []byte("h")
		dst := []byte(fmt.Sprintf("ic-crypto-tecdsa-%s-generator-h", curve.String()))
		h2p, err := Point.HashToPoint(curve, input, dst)
		assert.Nil(t, err)
		assert.Equal(t, 1, h.Equal(h2p))

	}
}

func TestK256WideReduceScalarExpectedValue(t *testing.T) {
	wideInput, _ := hex.DecodeString("5465872a72824a73539f16e825035c403a2596407116900d47141fca8cbfd9a638af75a71310b08fe6351dd302b820c86b15e71ea73c78c876c1f88338a0")
	scalar, err := Scalar.FromBytesWide(K256, wideInput)
	assert.Nil(t, err)
	assert.Equal(t, hex.EncodeToString(scalar.Serialize()), "5bc912d1f858a44805b5bcf9809751eb7ca8cd5efe9b9bef62374b55a857ba1b")
}

func TestScalarNegate(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curve := range all() {
		zero := Scalar.Zero(curve)
		for i := 0; i < 100; i++ {
			random := Scalar.Random(curve, rng)
			nRandom := Scalar.Zero(curve).Negate(random)
			shouldBeZero := Scalar.Zero(curve).Add(random, nRandom)
			assert.Equal(t, 1, shouldBeZero.Equal(zero))

			shouldBeZero = Scalar.Zero(curve).Add(nRandom, random)
			assert.Equal(t, 1, shouldBeZero.Equal(zero))
			assert.Equal(t, 1, shouldBeZero.IsZero())
		}
	}
}

func TestPointMulByNodeIndex(t *testing.T) {
	for _, curve := range all() {
		g := Point.GeneratorG(curve)
		for nodeIndex := 0; nodeIndex < 300; nodeIndex++ {
			gNi := g.MulByNodeIndex(common.NodeIndex(nodeIndex))
			scalar := Scalar.FromNodeIndex(curve, common.NodeIndex(nodeIndex))
			gs := g.ScalarMul(g, scalar)
			assert.Equal(t, 1, gs.Equal(gNi))
		}
	}
}
