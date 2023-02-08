package curve

import (
	"encoding/hex"
	"github.com/TraceBundy/tecdsa/common"
	"github.com/pkg/errors"
)

var (
	Point = point{}
)

type point struct{}

type EccPoint interface {
	CurveType() EccCurveType
	AddPoints(lhs, rhs EccPoint) EccPoint
	SubPoints(lhs, rhs EccPoint) EccPoint
	ScalarMul(other EccPoint, scalar EccScalar) EccPoint
	Double(other EccPoint) EccPoint
	MulByNodeIndex(scalar common.NodeIndex) EccPoint
	Clone() EccPoint
	Serialize() []byte
	SerializeTagged() []byte
	SerializeUncompressed() []byte
	Assign(other EccPoint) EccPoint
	AffineX() EccFieldElement
	AffineY() EccFieldElement
	IsInfinity() bool
	Equal(eccPoint EccPoint) int
}

func (p point) Identity(curve EccCurveType) EccPoint {
	var ec EccPoint
	switch curve {
	case K256:
		ec = K256Point.Identity()
	}
	return ec
}

func (p point) GeneratorG(curve EccCurveType) EccPoint {
	var ec EccPoint
	switch curve {
	case K256:
		ec = K256Point.NewK256G()
	}
	return ec
}

func (p point) GeneratorH(curve EccCurveType) EccPoint {
	var h []byte
	switch curve {
	case K256:
		h, _ = hex.DecodeString("037bdcfc024cf697a41fd3cda2436c843af5669e50042be3314a532d5b70572f59")
	}
	pt, err := p.Deserialize(curve, h)
	if err != nil {
		panic(err.Error())
	}
	return pt
}

func (p point) HashToPoint(curve EccCurveType, input []byte, domainSeparator []byte) (EccPoint, error) {
	return HashToCurveRo(curve, input, domainSeparator)
}
func (p point) FromFieldElems(x EccFieldElement, y EccFieldElement) (EccPoint, error) {
	if x.CurveType() != y.CurveType() {
		return nil, errors.New("curve mismatch")
	}
	curve := x.CurveType()
	xb := x.AsBytes()
	yb := y.AsBytes()
	encode := []byte{4}
	encode = append(encode, xb...)
	encode = append(encode, yb...)
	return p.DeserializeAnyFormat(curve, encode)
}

func (p point) MulPoints(pt1 EccPoint, scalar1 EccScalar, pt2 EccPoint, scalar2 EccScalar) EccPoint {
	var ec EccPoint
	switch pt1.CurveType() {
	case K256:
		ec = K256Point.NewK256().LinComb(pt1, scalar1, pt2, scalar2)
	}
	return ec
}

func (p point) Pedersen(scalar1 EccScalar, scalar2 EccScalar) EccPoint {
	g := p.GeneratorG(scalar1.CurveType())
	h := p.GeneratorH(scalar1.CurveType())
	return p.MulPoints(g, scalar1, h, scalar2)
}

func (p point) MulByG(scalar EccScalar) EccPoint {
	g := p.GeneratorG(scalar.CurveType())
	return g.ScalarMul(g, scalar)
}

func (p point) DeserializeTagged(curve EccCurveType, bytes []byte) (EccPoint, error) {
	if len(bytes) == 0 {
		return nil, errors.New("invalid point, bytes is empty")
	}
	return p.Deserialize(EccCurveType(bytes[0]), bytes[:])
}
func (p point) Deserialize(curve EccCurveType, bytes []byte) (EccPoint, error) {
	if len(bytes) != curve.PointBytes() {
		return nil, errors.New("invalid point")
	}

	flag := true
	for _, b := range bytes {
		if b != 0 {
			flag = false
			break
		}
	}
	if flag {
		return p.Identity(curve), nil
	}
	if bytes[0] != 2 && bytes[0] != 3 {
		return nil, errors.New("invalid point, first byte should be 2 or 3")
	}
	return p.DeserializeAnyFormat(curve, bytes)
}
func (p point) DeserializeAnyFormat(curve EccCurveType, bytes []byte) (pt EccPoint, err error) {
	switch curve {
	case K256:
		pt, err = K256Point.Deserialize(bytes)
	}
	return pt, err
}
