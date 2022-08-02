package curve

import "math/big"

var (
	Field = field{}
)

type field struct{}

type EccFieldElement interface {
	CurveType() EccCurveType
	IsZero() int
	AsBytes() []byte
	Add(lhs, rhs EccFieldElement) EccFieldElement
	Sub(lhs, rhs EccFieldElement) EccFieldElement
	Mul(lhs, rhs EccFieldElement) EccFieldElement
	Square(other EccFieldElement) EccFieldElement
	Equal(other EccFieldElement) int
	Clone() EccFieldElement
	Assign(other EccFieldElement) EccFieldElement
	CAssign(other EccFieldElement, flag int)
	Invert(other EccFieldElement) EccFieldElement
	Negate(other EccFieldElement) EccFieldElement
	Sqrt(other EccFieldElement) (EccFieldElement, int)
	Progenitor(other EccFieldElement) EccFieldElement
	Sign() uint8
	BigInt() *big.Int
}

func (f field) Zero(curve EccCurveType) EccFieldElement {
	var fe EccFieldElement
	switch curve {
	case K256:
		fe = K256Field.Zero()

	}
	return fe
}

func (f field) One(curve EccCurveType) EccFieldElement {
	var fe EccFieldElement
	switch curve {
	case K256:
		fe = K256Field.One()
	}
	return fe
}

func (f field) A(curve EccCurveType) EccFieldElement {
	var fe EccFieldElement
	switch curve {
	case K256:
		fe = K256Field.FieldA()
	}
	return fe
}

func (f field) B(curve EccCurveType) EccFieldElement {
	var fe EccFieldElement
	switch curve {
	case K256:
		fe = K256Field.FieldB()
	}
	return fe
}

func (f field) SswuA(curve EccCurveType) EccFieldElement {
	var fe EccFieldElement
	switch curve {
	case K256:
		fe = K256Field.FieldSswuA()
	}
	return fe
}

func (f field) SswuB(curve EccCurveType) EccFieldElement {
	var fe EccFieldElement
	switch curve {
	case K256:
		fe = K256Field.FieldSswuB()

	}
	return fe
}

func (f field) SswuZ(curve EccCurveType) EccFieldElement {
	var fe EccFieldElement
	switch curve {
	case K256:
		fe = K256Field.FieldSswuZ()

	}
	return fe
}

func (f field) SswuC2(curve EccCurveType) EccFieldElement {
	var fe EccFieldElement
	switch curve {
	case K256:
		fe = K256Field.FieldSswuC2()

	}
	return fe
}

func (f field) FromBytes(curve EccCurveType, bytes []byte) (fe EccFieldElement, err error) {
	switch curve {
	case K256:
		fe, err = K256Field.FromBytes(bytes)
	}
	return fe, err
}

func (f field) FromBytesWide(curve EccCurveType, bytes []byte) (EccFieldElement, error) {
	var fe EccFieldElement
	switch curve {
	case K256:
		fe = K256Field.FromBytesWide(bytes)
	}
	return fe, nil
}
