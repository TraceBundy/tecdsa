package poly

import (
	crand "crypto/rand"
	"encoding/hex"
	"github.com/TraceBundy/tecdsa/curve"
	"github.com/TraceBundy/tecdsa/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOpeningSerialize(t *testing.T) {
	s := SimpleCommitmentOpening([1]curve.EccScalar{curve.Scalar.One(curve.K256)})
	bytes, err := s.Serialize()
	assert.Nil(t, err)
	t.Log(hex.EncodeToString(bytes))
	open, err := commitmentOpening{}.Deserialize(bytes)
	assert.Nil(t, err)
	t.Log(open.ToString())
	assert.Equal(t, 1, s[0].Equal(open.(*SimpleCommitmentOpening)[0]))
}

func TestCommitmentSerialize(t *testing.T) {
	s := SimpleCommitment{points: []curve.EccPoint{curve.Point.GeneratorG(curve.K256)}}
	bytes, err := s.Serialize()
	assert.Nil(t, err)
	t.Log(hex.EncodeToString(bytes))
	open, err := polynomialCommitment{}.Deserialize(bytes)
	assert.Nil(t, err)
	assert.Equal(t, open.(*SimpleCommitment).Len(), len(s.points))
}

func TestPolySimpleCommitments(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curve := range all() {
		for num := 1; num < 50; num++ {
			poly := Poly.Random(curve, num, rng)
			_, err := SimpleCM.Create(poly, num)
			assert.Nil(t, err)
		}
	}
}

func TestPolyPedersenCommitments(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curve := range all() {
		for num := 1; num < 50; num++ {
			polya := Poly.Random(curve, num, rng)
			polyb := Poly.Random(curve, num, rng)
			cab, err := PedersenCM.Create(polya, polyb, num)
			assert.Nil(t, err)
			cba, err := PedersenCM.Create(polyb, polya, num)
			assert.Nil(t, err)
			assert.Equal(t, 0, cab.Equal(cba))
		}
	}
}
