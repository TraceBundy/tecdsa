package poly

import (
	"github.com/TraceBundy/tecdsa/curve"
	"github.com/TraceBundy/tecdsa/rand"
	"github.com/pkg/errors"
	"modernc.org/mathutil"
)

var (
	Poly = polynomial{}
)

type polynomial struct {
}
type Polynomial struct {
	curve        curve.EccCurveType
	coefficients []curve.EccScalar
}

func (polynomial) New(curve curve.EccCurveType, coefficients []curve.EccScalar) *Polynomial {
	return &Polynomial{
		curve:        curve,
		coefficients: coefficients,
	}
}

func (polynomial) Zero(curveType curve.EccCurveType) *Polynomial {
	return &Polynomial{
		curve:        curveType,
		coefficients: []curve.EccScalar{},
	}
}

func (polynomial) Random(curveType curve.EccCurveType, num int, rng rand.Rand) *Polynomial {
	coefficients := make([]curve.EccScalar, num, num)
	for i := range coefficients {
		coefficients[i] = curve.Scalar.Random(curveType, rng)
	}
	return &Polynomial{
		curve:        curveType,
		coefficients: coefficients,
	}
}

func (polynomial) RandomWithConstant(constant curve.EccScalar, num int, rng rand.Rand) (*Polynomial, error) {
	if num == 0 {
		return nil, errors.New("Cannot have degree=0 polynomial with given constant")
	}
	curveType := constant.CurveType()
	coefficients := make([]curve.EccScalar, num, num)
	coefficients[0] = constant
	for i := range coefficients {
		if i != 0 {
			coefficients[i] = curve.Scalar.Random(curveType, rng)
		}
	}
	return &Polynomial{
		curve:        curveType,
		coefficients: coefficients,
	}, nil
}

func (p Polynomial) CurveType() curve.EccCurveType {
	return p.curve
}

func (p Polynomial) Coeff(idx int) curve.EccScalar {
	if idx < len(p.coefficients) {
		return curve.Scalar.Zero(p.curve).Assign(p.coefficients[idx])
	}
	return curve.Scalar.Zero(p.curve)
}

/// Return the count of non-zero coefficients
func (p Polynomial) NonZeroCoefficients() int {
	zeros := 0
	for _, c := range p.coefficients {
		if c.IsZero() == 1 {
			zeros++
		}
	}
	return len(p.coefficients) - zeros
}
func (p Polynomial) IsZero() int {
	flag := 0
	if p.NonZeroCoefficients() == 0 {
		flag = 1
	}
	return flag
}

// Polynomial addition
func (p *Polynomial) Add(lhs, rhs *Polynomial) *Polynomial {
	max := mathutil.Max(len(lhs.coefficients), len(rhs.coefficients))
	res := make([]curve.EccScalar, max, max)
	for i := 0; i < max; i++ {
		x := lhs.Coeff(i)
		y := rhs.Coeff(i)
		res[i] = x.Add(x, y)
	}
	p.coefficients = res
	return p
}

// Compute product of a polynomial and a polynomial
func (p *Polynomial) Mul(lhs, rhs *Polynomial) *Polynomial {
	curveType := lhs.CurveType()
	nCoeffs := mathutil.Max(len(lhs.coefficients)+len(rhs.coefficients), 1) - 1
	coeffs := make([]curve.EccScalar, nCoeffs, nCoeffs)
	for i := range coeffs {
		coeffs[i] = curve.Scalar.Zero(curveType)
	}
	for i, ca := range lhs.coefficients {
		for j, cb := range rhs.coefficients {
			tmp := curve.Scalar.Zero(curveType).Mul(ca, cb)
			coeffs[i+j] = coeffs[i+j].Add(coeffs[i+j], tmp)
		}
	}
	p.coefficients = coeffs
	return p
}

func (p *Polynomial) MulScalar(lhs *Polynomial, scalar curve.EccScalar) *Polynomial {
	coeffs := make([]curve.EccScalar, len(lhs.coefficients), len(lhs.coefficients))
	for i := range coeffs {
		coeffs[i] = curve.Scalar.Zero(lhs.curve).Mul(p.coefficients[i], scalar)
	}
	p.coefficients = coeffs
	return p
}

/// Evaluate the polynomial at x
///
/// This uses Horner's method: <https://en.wikipedia.org/wiki/Horner%27s_method>

func (p *Polynomial) EvaluateAt(x curve.EccScalar) curve.EccScalar {
	if len(p.coefficients) == 0 {
		return curve.Scalar.Zero(p.curve)
	}
	index := len(p.coefficients) - 1
	ans := p.Coeff(index)
	for i := index - 1; i >= 0; i-- {
		coeff := p.coefficients[i].Clone()
		ans = ans.Mul(ans, x)
		ans = ans.Add(ans, coeff)
	}
	return ans
}

func (p *Polynomial) Equal(rhs *Polynomial) int {
	if p.curve != rhs.curve {
		return 0
	}
	max := mathutil.Max(len(p.coefficients), len(rhs.coefficients))
	for i := 0; i < max; i++ {
		if p.Coeff(i).Equal(rhs.Coeff(i)) == 0 {
			return 0
		}
	}
	return 1
}

// Polynomial interpolation
func (p polynomial) Interpolate(curveType curve.EccCurveType, samples [][2]curve.EccScalar) (*Polynomial, error) {
	if len(samples) == 0 {
		return Poly.Zero(curveType), nil
	}
	one := curve.Scalar.One(curveType)
	poly := Poly.New(curveType, []curve.EccScalar{samples[0][1].Clone()})
	s0 := samples[0][0].Clone()
	s0 = s0.Negate(s0)
	base := Poly.New(curveType, []curve.EccScalar{s0.Clone(), one.Clone()})
	for _, s := range samples[1:] {
		x, y := s[0].Clone(), s[1].Clone()
		diff := curve.Scalar.Zero(curveType).Sub(y, poly.EvaluateAt(x))
		inv := base.EvaluateAt(x)
		inv = inv.Invert(inv)

		if inv.IsZero() == 1 {
			return nil, errors.New("inv is zero")
		}
		diff = diff.Mul(diff, inv)
		base = base.MulScalar(base, diff)
		poly = poly.Add(poly, base)
		base = base.Mul(base, Poly.New(curveType, []curve.EccScalar{x.Negate(x), one}))
	}
	return poly, nil
}
