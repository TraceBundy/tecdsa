package curve

import (
	"github.com/TraceBundy/tecdsa/common"
	"github.com/coinbase/kryptology/pkg/core/curves/native"
	"github.com/coinbase/kryptology/pkg/core/curves/native/k256"
	"github.com/coinbase/kryptology/pkg/core/curves/native/k256/fp"
	"github.com/fxamacker/cbor/v2"
	"math/big"
	"math/bits"
)

var (
	K256Point = EccK256Point{}
)

type EccK256Point struct{}

type Secp256k1Point struct {
	point *native.EllipticPoint
}

func (EccK256Point) NewK256() *Secp256k1Point {
	return &Secp256k1Point{point: k256.K256PointNew()}
}

func (EccK256Point) NewK256G() *Secp256k1Point {
	return &Secp256k1Point{point: k256.K256PointNew().Generator()}
}

func (EccK256Point) NewK256H() *Secp256k1Point {
	return nil
	//return &Secp256k1Point{point: k256.K256PointNew().}
}

func (EccK256Point) Identity() *Secp256k1Point {
	return &Secp256k1Point{point: k256.K256PointNew().Identity()}
}
func (e EccK256Point) Deserialize(bytes []byte) (*Secp256k1Point, error) {
	ec, err := Encode.FromBytes(bytes)
	if err != nil {
		return nil, err
	}
	return e.fromEncodedPoint(ec)
}

func (e EccK256Point) fromUncompressed(xb, yb []byte) (*Secp256k1Point, error) {
	x := fp.K256FpNew().SetBigInt(new(big.Int).SetBytes(xb))

	y := fp.K256FpNew().SetBigInt(new(big.Int).SetBytes(yb))

	value := k256.K256PointNew()
	value.X = x
	value.Y = y
	value.Z.SetOne()
	return &Secp256k1Point{point: value}, nil
}
func (e EccK256Point) decompress(bytes []byte, sign int) (*Secp256k1Point, error) {
	x := fp.K256FpNew().SetBigInt(new(big.Int).SetBytes(bytes))

	value := k256.K256PointNew().Identity()
	rhs := fp.K256FpNew()
	p := k256.K256PointNew()
	p.Arithmetic.RhsEq(rhs, x)
	// test that rhs is quadratic residue
	// if not, then this Point is at infinity
	y, wasQr := fp.K256FpNew().Sqrt(rhs)
	if wasQr {
		// fix the sign
		sigY := int(y.Bytes()[0] & 1)
		if sigY != sign {
			y.Neg(y)
		}
		value.X = x
		value.Y = y
		value.Z.SetOne()
	}
	return &Secp256k1Point{point: value}, nil
}
func (e EccK256Point) fromEncodedPoint(encodePoint EncodePoint) (pt *Secp256k1Point, err error) {
	cd := encodePoint.Coordinates()
	switch c := cd.(type) {
	case *IdentityCoordinates:
		pt = e.Identity()
	case *CompactCoordinates:
		pt, err = e.decompress(c.x, 0)
	case *CompressedCoordinates:
		choice := 0
		if c.yIsOdd {
			choice = 1
		}
		pt, err = e.decompress(c.x, choice)
	case *UnCompressedCoordinates:
		pt, err = e.fromUncompressed(c.x, c.y)
	}
	return pt, err
}
func (s Secp256k1Point) CurveType() EccCurveType {
	return K256
}

func (s *Secp256k1Point) AddPoints(lhs, rhs EccPoint) EccPoint {
	l := lhs.(*Secp256k1Point)
	r := rhs.(*Secp256k1Point)
	s.point.Add(l.point, r.point)
	return s
}

func (s *Secp256k1Point) SubPoints(lhs, rhs EccPoint) EccPoint {
	l := lhs.(*Secp256k1Point)
	r := rhs.(*Secp256k1Point)
	s.point.Sub(l.point, r.point)
	return s
}

func (s *Secp256k1Point) Double(other EccPoint) EccPoint {
	o := other.(*Secp256k1Point)
	s.point.Double(o.point)
	return s
}

func (s Secp256k1Point) Clone() EccPoint {
	return &Secp256k1Point{
		point: k256.K256PointNew().Set(s.point),
	}
}

func (s *Secp256k1Point) ScalarMul(other EccPoint, scalar EccScalar) EccPoint {
	o := other.(*Secp256k1Point)
	f := scalar.(*Secp256k1Scalar)
	s.point.Mul(o.point, f.scalar)
	return s
}
func (s *Secp256k1Point) MulByNodeIndex(scalar common.NodeIndex) EccPoint {
	s64 := uint64(scalar + 1)
	bits := 64 - bits.LeadingZeros64(uint64(s64))
	res := EccPoint(K256Point.Identity())
	for b := 0; b < bits; b++ {
		res = res.Double(res)
		if (s64 >> (bits - 1 - b) & 1) == 1 {
			res = res.AddPoints(res, s)
		}
	}
	return res
}

func (s *Secp256k1Point) LinComb(pt1 EccPoint, scalar1 EccScalar, pt2 EccPoint, scalar2 EccScalar) EccPoint {

	s.point.SumOfProducts([]*native.EllipticPoint{pt1.(*Secp256k1Point).point, pt2.(*Secp256k1Point).point}, []*native.Field{scalar1.(*Secp256k1Scalar).scalar, scalar2.(*Secp256k1Scalar).scalar})
	return s
}

func (s Secp256k1Point) encodePoint(compress bool) []byte {
	p := k256.K256PointNew().ToAffine(s.point)
	x := &Secp256k1Field{field: p.GetX()}
	y := &Secp256k1Field{field: p.GetY()}
	choice := 0
	if s.point.IsIdentity() {
		choice = 1
	}
	encode := Encode.ConditionalSelect(Encode.FromAffineCoordinates(x.AsBytes(), y.AsBytes(), compress), Encode.Identity(), choice)
	result := make([]byte, 33, 33)
	copy(result[0:encode.Len()], encode.AsBytes())
	return result
}
func (s Secp256k1Point) Serialize() []byte {
	return s.encodePoint(true)
}

func (s Secp256k1Point) Equal(eccPoint EccPoint) int {
	return s.point.Equal(eccPoint.(*Secp256k1Point).point)
}

func (s *Secp256k1Point) Assign(eccPoint EccPoint) EccPoint {
	s.point.Set(eccPoint.(*Secp256k1Point).point)
	return s
}

func (s Secp256k1Point) SerializeTagged() []byte {
	bytes := make([]byte, 1+s.CurveType().PointBytes(), 1+s.CurveType().PointBytes())
	bytes[0] = s.CurveType().Tag()
	copy(bytes[1:], s.Serialize())
	return bytes
}

func (s Secp256k1Point) SerializeUncompressed() []byte {
	return s.encodePoint(false)
}

func (s Secp256k1Point) AffineX() EccFieldElement {
	return &Secp256k1Field{field: s.point.GetX()}
}

func (s Secp256k1Point) AffineY() EccFieldElement {
	return &Secp256k1Field{field: s.point.GetY()}
}

func (s Secp256k1Point) IsInfinity() bool {
	return s.point.IsIdentity()
}

func (s Secp256k1Point) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(s.SerializeTagged())
}

func (s *Secp256k1Point) UnmarshalCBOR(data []byte) error {
	var bytes []byte
	if err := cbor.Unmarshal(data, &bytes); err != nil {
		return err
	}
	tmp, err := K256Point.Deserialize(bytes[1:])
	if err != nil {
		return err
	}
	s.point = tmp.point
	return nil
}
