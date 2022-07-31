package poly

import (
	crand "crypto/rand"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func all() []curve.EccCurveType {
	return []curve.EccCurveType{curve.K256}
}

func newArray(a curve.EccScalar, size int) []curve.EccScalar {
	coeffs := make([]curve.EccScalar, size, size)
	for i := range coeffs {
		coeffs[i] = curve.Scalar.Zero(a.CurveType()).Assign(a)
	}
	return coeffs
}
func TestPolyZeroTimesZeroIsZero(t *testing.T) {
	for _, curveType := range all() {
		zero := curve.Scalar.Zero(curveType)
		for coeffs := 0; coeffs < 10; coeffs++ {
			zpoly := Poly.New(curveType, newArray(zero, coeffs))
			assert.Equal(t, 1, zpoly.IsZero())
			zpoly2 := zpoly.Mul(zpoly, zpoly)
			assert.Equal(t, 1, zpoly2.IsZero())
		}
	}
}

func TestPolyAConstantPolyIsConstant(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curveType := range all() {
		constant := curve.Scalar.Random(curveType, rng)
		poly := Poly.New(curveType, []curve.EccScalar{constant.Clone()})
		for i := 0; i < 100; i++ {
			r := curve.Scalar.Random(curveType, rng)
			assert.Equal(t, 1, poly.EvaluateAt(r).Equal(constant))
		}
	}
}

func TestPolySimplePolynomialX1(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curveType := range all() {
		zero := curve.Scalar.Zero(curveType)
		one := curve.Scalar.One(curveType)
		poly := Poly.New(curveType, []curve.EccScalar{one.Clone(), one.Clone()})
		assert.Equal(t, 1, poly.EvaluateAt(zero).Equal(one))
		for trial := 0; trial < 100; trial++ {
			r := curve.Scalar.Random(curveType, rng)
			rPlus := r.Clone().Add(r, one)
			assert.Equal(t, 1, poly.EvaluateAt(r).Equal(rPlus))
		}
	}
}

func TestPolySimplePolynomialX2X1(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curveType := range all() {
		zero := curve.Scalar.Zero(curveType)
		one := curve.Scalar.One(curveType)
		poly := Poly.New(curveType, []curve.EccScalar{one.Clone(), one.Clone(), one.Clone()})
		assert.Equal(t, 1, poly.EvaluateAt(zero).Equal(one))
		for trial := 0; trial < 100; trial++ {
			r := curve.Scalar.Random(curveType, rng)
			r2 := r.Clone().Mul(r, r)
			r2Plus := r2.Clone().Add(r2, r)
			r2Plus = r2Plus.Add(r2Plus, one)
			assert.Equal(t, 1, poly.EvaluateAt(r).Equal(r2Plus))
		}
	}
}

func TestPolyInterpolateWorks(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curveType := range all() {
		for num := 0; num < 50; num++ {
			poly := Poly.Random(curveType, num, rng)
			samples := make([][2]curve.EccScalar, num, num)
			for i := 0; i < num; i++ {
				r := curve.Scalar.Random(curveType, rng)
				pr := poly.EvaluateAt(r)
				samples[i] = [2]curve.EccScalar{r, pr}
			}
			interp, err := Poly.Interpolate(curveType, samples)
			if err == nil {
				assert.Equal(t, 1, poly.Equal(interp))
			}
		}
	}
}

func TestPolyInterpolateFailsIfInsufficientPoints(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curveType := range all() {
		for num := 1; num < 50; num++ {
			poly := Poly.Random(curveType, num, rng)
			samples := make([][2]curve.EccScalar, num-1, num-1)
			for i := 0; i < num-1; i++ {
				r := curve.Scalar.Random(curveType, rng)
				pr := poly.EvaluateAt(r)
				samples[i] = [2]curve.EccScalar{r, pr}
			}
			p, err := Poly.Interpolate(curveType, samples)
			if err == nil {
				assert.Equal(t, 0, p.Equal(poly))
			}
		}
	}
}

func TestPolyInterpolateErrorsOnDuplicateInputs(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curveType := range all() {
		for num := 0; num < 50; num++ {
			poly := Poly.Random(curveType, num, rng)
			var samples [][2]curve.EccScalar
			dupr := curve.Scalar.Random(curveType, rng)
			duppr := poly.EvaluateAt(dupr)
			for i := 0; i <= num; i++ {
				samples = append(samples, [2]curve.EccScalar{dupr, duppr})
			}
			for i := 0; i <= num; i++ {
				r := curve.Scalar.Random(curveType, rng)
				pr := poly.EvaluateAt(r)
				samples = append(samples, [2]curve.EccScalar{r, pr})
				samples = append(samples, [2]curve.EccScalar{dupr, duppr})
			}
			_, err := Poly.Interpolate(curveType, samples)
			assert.NotNil(t, err)
		}
	}
}

func TestPolyInterpolateIsResilientToLowXPoints(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curveType := range all() {
		for num := 0; num < 50; num++ {
			poly := Poly.Random(curveType, num, rng)
			assert.Equal(t, num, poly.NonZeroCoefficients())
			one := curve.Scalar.One(curveType)
			x := curve.Scalar.Zero(curveType)
			var samples [][2]curve.EccScalar
			for i := 0; i <= num; i++ {
				px := poly.EvaluateAt(x)
				samples = append(samples, [2]curve.EccScalar{x.Clone(), px.Clone()})
				x = x.Add(x, one)
			}
			interp, err := Poly.Interpolate(curveType, samples)
			assert.Nil(t, err)
			assert.Equal(t, 1, interp.Equal(poly))

		}
	}
}

func TestPolyThresholdSecretSharing(t *testing.T) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	for _, curveType := range all() {
		zero := curve.Scalar.Zero(curveType)
		secret := curve.Scalar.Random(curveType, rng)
		for num := 1; num < 50; num++ {
			poly, err := Poly.RandomWithConstant(secret, num, rng)
			assert.Nil(t, err)
			assert.Equal(t, num, poly.NonZeroCoefficients())
			shares := make([][2]curve.EccScalar, num+1, num+1)
			for i := 0; i < num+1; i++ {
				r := curve.Scalar.Random(curveType, rng)
				pr := poly.EvaluateAt(r)
				shares[i] = [2]curve.EccScalar{r, pr}
			}
			interp, err := Poly.Interpolate(curveType, shares)
			assert.Nil(t, err)
			assert.Equal(t, 1, interp.EvaluateAt(zero).Equal(secret))
		}
	}
}
