package poly

import (
	crand "crypto/rand"
	"encoding/hex"
	"github.com/TraceBundy/tecdsa/rand"
	"github.com/TraceBundy/tecdsa/seed"
	"github.com/TraceBundy/tecdsa/common"
	"github.com/TraceBundy/tecdsa/curve"
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
)

func TestPolyLagrangeCoefficientsAtZeroAreCorrect(t *testing.T) {
	curveType := curve.K256
	intToScalar := func(curveType curve.EccCurveType, ints []int64) []curve.EccScalar {
		scalars := make([]curve.EccScalar, len(ints), len(ints))
		for i := 0; i < len(ints); i++ {
			s := curve.Scalar.FromUint64(curveType, uint64(math.Abs(float64(ints[i]))))
			if ints[i] < 0 {
				s.Negate(s)
			}
			scalars[i] = s
		}
		return scalars
	}
	xv := []common.NodeIndex{1, 2, 3, 6}
	numerators := intToScalar(curveType, []int64{3 * 4 * 7, 2 * 4 * 7, 2 * 3 * 7, 2 * 3 * 4})
	denominators := intToScalar(curveType, []int64{
		(3 - 2) * (4 - 2) * (7 - 2),
		(2 - 3) * (4 - 3) * (7 - 3),
		(2 - 4) * (3 - 4) * (7 - 4),
		(2 - 7) * (3 - 7) * (4 - 7)})
	computed := make([]curve.EccScalar, len(numerators), len(numerators))
	for i := 0; i < len(numerators); i++ {
		numerator := numerators[i].Clone()
		denominator := denominators[i].Clone()
		computed[i] = numerator.Mul(numerator, denominator.Invert(denominator))
	}

	observed, err := Lagrange.AtValue(curve.Scalar.Zero(curveType), xv)
	assert.Nil(t, err)
	assert.Equal(t, 1, observed.Equal(&LagrangeCoefficients{computed}))
}
func atZero(t *testing.T, x []common.NodeIndex, y []curve.EccPoint) (curve.EccPoint, error) {
	coeff, err := Lagrange.AtZero(y[0].CurveType(), x)
	if err != nil {
		return nil, err
	}
	p, err := coeff.InterpolatePoint(y)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func randomNodeIndexes(count int) []common.NodeIndex {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	set := make(map[common.NodeIndex]struct{})
	for len(set) != count {
		r := rng.Uint32()
		set[common.NodeIndex(r)] = struct{}{}
	}
	var res []common.NodeIndex
	for k, _ := range set {
		res = append(res, k)
	}
	return res
}

func TestPointInterpolationAtZero(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curveType := range all() {
		for num := 1; num < 30; num++ {
			sk := curve.Scalar.Random(curveType, rng)
			pk := curve.Point.MulByG(sk)
			poly, err := Poly.RandomWithConstant(sk, num, rng)
			assert.Nil(t, err)
			x := randomNodeIndexes(num)
			y := make([]curve.EccPoint, num, num)
			for i, r := range x {
				pr := poly.EvaluateAt(curve.Scalar.FromNodeIndex(curveType, r))
				gpr := curve.Point.MulByG(pr)
				y[i] = gpr
			}
			g0, _ := atZero(t, x, y)
			assert.Equal(t, 1, g0.Equal(pk))
		}
	}
}

func TestPointInterpolationAtValue(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curveType := range all() {
		for num := 1; num < 30; num++ {
			value := curve.Scalar.Random(curveType, rng)
			poly := Poly.Random(curveType, num, rng)
			x := randomNodeIndexes(num)
			y := make([]curve.EccPoint, num, num)
			for i, r := range x {
				pr := poly.EvaluateAt(curve.Scalar.FromNodeIndex(curveType, r))
				gpr := curve.Point.MulByG(pr)
				y[i] = gpr
			}
			coeffs, err := Lagrange.AtValue(value, x)
			assert.Nil(t, err)
			p, err := coeffs.InterpolatePoint(y)
			assert.Nil(t, err)
			assert.Equal(t, 1, p.Equal(curve.Point.MulByG(poly.EvaluateAt(value))))
		}
	}
}

func TestPointInterpolationAtZeroRejectsDuplicates(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curveType := range all() {
		for num := 1; num < 30; num++ {
			value := curve.Scalar.Random(curveType, rng)
			poly, err := Poly.RandomWithConstant(value, num, rng)
			assert.Nil(t, err)
			x := randomNodeIndexes(num)
			x = append(x, x[int(rng.Uint32())%len(x)])
			y := make([]curve.EccPoint, len(x), len(x))
			for i, r := range x {
				pr := poly.EvaluateAt(curve.Scalar.FromNodeIndex(curveType, r))
				gpr := curve.Point.MulByG(pr)
				y[i] = gpr
			}
			_, err = atZero(t, x, y)
			assert.NotNil(t, err)
		}
	}
}

func TestPointInterpolationAtZeroFailsWithInsufficientShares(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curveType := range all() {
		for num := 2; num < 20; num++ {
			sk := curve.Scalar.Random(curveType, rng)
			pk := curve.Point.MulByG(sk)
			poly, err := Poly.RandomWithConstant(sk, num, rng)
			assert.Nil(t, err)
			x := randomNodeIndexes(num - 1)
			y := make([]curve.EccPoint, num-1, num-1)
			for i, r := range x {
				pr := poly.EvaluateAt(curve.Scalar.FromNodeIndex(curveType, r))
				gpr := curve.Point.MulByG(pr)
				y[i] = gpr
			}
			p, err := atZero(t, x, y)
			if err == nil {
				assert.Equal(t, 0, p.Equal(pk))
			}
		}
	}
}

func TestSimpleCommitmentStableRepresentationIsStable(t *testing.T) {
	simpleCommitmentBytes := func(curveType curve.EccCurveType, sz int) []byte {
		key := make([]byte, sz, sz)
		for i, _ := range key {
			key[i] = 42
		}
		rng := seed.FromBytes(key).Rng()
		polynomial := Poly.Random(curveType, sz, rng)
		opening, err := SimpleCM.Create(polynomial, sz)
		assert.Nil(t, err)
		return opening.StableRepresentation()
	}

	assert.Equal(t, "53010269a513d6375661fb245a5b66206a85671568178e0608b4585bee50542be4999a", hex.EncodeToString(simpleCommitmentBytes(curve.K256, 1)))
	assert.Equal(t, "5301034af5f78220f96e265d9c93af4463b7b91a2dc1ef1db105913cb85024c697f79c036ac66cf30781414b2cb7e4e5ee13885e3d6c8049f2cf623f2d24f37de1d08432", hex.EncodeToString(simpleCommitmentBytes(curve.K256, 2)))
}

func TestPedersenCommitmentStableRepresentationIsStable(t *testing.T) {
	pedersenCommitmentBytes := func(curveType curve.EccCurveType, sz int) []byte {
		key := make([]byte, sz, sz)
		for i, _ := range key {
			key[i] = 42
		}
		rng := seed.FromBytes(key).Rng()
		polynomial := Poly.Random(curveType, sz, rng)
		mask := Poly.Random(curveType, sz, rng)
		opening, err := PedersenCM.Create(polynomial, mask, sz)
		assert.Nil(t, err)
		return opening.StableRepresentation()
	}

	assert.Equal(t, "500103e4febce7716f1f46b4c3ce26332c71ac013d901bf214bcf04a02c331ac9df8fb", hex.EncodeToString(pedersenCommitmentBytes(curve.K256, 1)))
	assert.Equal(t, "500103dcd8d3bf27056abab419a773e1eb8f066968a427af43148595b105d2875b8804036bcc68f6a1547bdc684a95e8dde462891e130fd35bf79911e0f503a6469cb08f", hex.EncodeToString(pedersenCommitmentBytes(curve.K256, 2)))
}
