package poly

import (
	"github.com/TraceBundy/tecdsa/common"
	"github.com/TraceBundy/tecdsa/curve"
	"github.com/pkg/errors"
)

var (
	Lagrange = lagrangeCoefficients{}
)

type LagrangeCoefficients struct {
	coefficients []curve.EccScalar
}
type lagrangeCoefficients struct {
}

func (lagrangeCoefficients) New(coefficients []curve.EccScalar) (*LagrangeCoefficients, error) {
	if len(coefficients) == 0 {
		return nil, errors.New("coefficients is empty")
	}
	return &LagrangeCoefficients{
		coefficients: coefficients,
	}, nil
}

func (l *LagrangeCoefficients) Equal(other *LagrangeCoefficients) int {
	if len(l.coefficients) != len(other.coefficients) {
		return 0
	}
	for i := 0; i < len(l.coefficients); i++ {
		if l.coefficients[i].Equal(other.coefficients[i]) == 0 || l.coefficients[i].CurveType() != other.coefficients[i].CurveType() {
			return 0
		}
	}
	return 1
}

func (l *LagrangeCoefficients) Coefficients() []curve.EccScalar {
	return l.coefficients
}

/// Given a list of samples `(x, f(x) * g)` for a set of unique `x`, some
/// polynomial `f`, and some elliptic curve point `g`, returns `f(value) * g`.
///
/// See: <https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach>
func (l *LagrangeCoefficients) InterpolatePoint(y []curve.EccPoint) (curve.EccPoint, error) {
	if len(y) != len(l.coefficients) {
		return nil, errors.New("interpolation error")
	}
	curveType := l.coefficients[0].CurveType()
	result := curve.Point.Identity(curveType)
	for i := 0; i < len(y); i++ {
		coefficient, sample := l.coefficients[i].Clone(), y[i].Clone()
		result = result.AddPoints(result, sample.ScalarMul(sample, coefficient))
	}
	return result, nil
}

func (l *LagrangeCoefficients) InterpolateScalar(y []curve.EccScalar) (curve.EccScalar, error) {
	if len(y) != len(l.coefficients) {
		return nil, errors.New("interpolation error")
	}
	curveType := l.coefficients[0].CurveType()
	result := curve.Scalar.Zero(curveType)
	for i := 0; i < len(y); i++ {
		coefficient, sample := l.coefficients[i].Clone(), y[i].Clone()
		result = result.Add(result, sample.Mul(sample, coefficient))
	}
	return result, nil
}
func checkForDuplicates(nodeIndex []common.NodeIndex) error {
	set := make(map[common.NodeIndex]struct{})
	for _, i := range nodeIndex {
		if _, ok := set[i]; ok {
			return errors.New("duplicate node index")
		}
		set[i] = struct{}{}
	}
	return nil
}

func (l *lagrangeCoefficients) AtZero(curveType curve.EccCurveType, samples []common.NodeIndex) (*LagrangeCoefficients, error) {
	return l.AtValue(curve.Scalar.Zero(curveType), samples)
}

func (l *lagrangeCoefficients) AtValue(value curve.EccScalar, samples []common.NodeIndex) (*LagrangeCoefficients, error) {
	if len(samples) == 0 {
		return nil, errors.New("samples is empty")
	}

	curveType := value.CurveType()
	if len(samples) == 1 {
		return &LagrangeCoefficients{coefficients: []curve.EccScalar{curve.Scalar.One(curveType)}}, nil
	}
	if err := checkForDuplicates(samples); err != nil {
		return nil, err
	}
	scalars := make([]curve.EccScalar, len(samples), len(samples))
	for i, _ := range scalars {
		scalars[i] = curve.Scalar.FromNodeIndex(curveType, samples[i])
	}

	numerator := make([]curve.EccScalar, len(samples), len(samples))
	tmp := curve.Scalar.One(curveType)
	numerator[0] = tmp.Clone()
	for i := 0; i < len(scalars)-1; i++ {
		x := scalars[i].Clone()
		tmp = tmp.Mul(tmp, x.Sub(x, value))
		numerator[i+1] = tmp.Clone()
	}

	tmp = curve.Scalar.One(curveType)
	for i := len(scalars) - 1; i > 0; i-- {
		x := scalars[i].Clone()
		tmp = tmp.Mul(tmp, x.Sub(x, value))
		numerator[i-1] = numerator[i-1].Mul(numerator[i-1], tmp)
	}
	for i := 0; i < len(scalars); i++ {
		lagrange, xi := numerator[i], scalars[i]
		denom := curve.Scalar.One(curveType)
		for j := 0; j < len(scalars); j++ {
			xj := scalars[j].Clone()
			if xi.Equal(xj) == 0 {
				diff := xj.Sub(xj, xi)
				denom = denom.Mul(denom, diff)
			}
		}

		inv := denom.Invert(denom)
		if inv.IsZero() == 1 {
			return nil, errors.New("interpolation error")
		}
		lagrange = lagrange.Mul(lagrange, inv)
	}
	return &LagrangeCoefficients{
		coefficients: numerator,
	}, nil
}
