package curve

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/coinbase/kryptology/pkg/core/curves/native"
	"github.com/coinbase/kryptology/pkg/core/curves/native/k256/fq"
	"github.com/fxamacker/cbor/v2"
	"math/big"
)

var (
	K256Scalar = EccK256Scalar{}
	GroupOrder = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	OrderHalf  = fq.K256FqNew().SetBigInt(new(big.Int).Div(GroupOrder, big.NewInt(2)))
)

type EccK256Scalar struct{}
type Secp256k1Scalar struct {
	scalar *native.Field
}

func (EccK256Scalar) Deserialize(bytes []byte) (*Secp256k1Scalar, error) {
	var buf [32]byte
	copy(buf[:], common.ReverseBytes(bytes))
	field, err := fq.K256FqNew().SetBytes(&buf)
	if err != nil {
		return nil, err
	}
	return &Secp256k1Scalar{
		scalar: field,
	}, nil
}
func (EccK256Scalar) Zero() *Secp256k1Scalar {
	return &Secp256k1Scalar{
		scalar: fq.K256FqNew().SetZero(),
	}
}

func (EccK256Scalar) One() *Secp256k1Scalar {
	return &Secp256k1Scalar{
		scalar: fq.K256FqNew().SetOne(),
	}
}

func (EccK256Scalar) FromUint64(n uint64) *Secp256k1Scalar {
	return &Secp256k1Scalar{
		scalar: fq.K256FqNew().SetUint64(n),
	}
}

func (EccK256Scalar) FromWideBytes(bytes []byte) *Secp256k1Scalar {
	var r [64]byte
	copy(r[:len(bytes)], common.ReverseBytes(bytes))

	return &Secp256k1Scalar{
		scalar: fq.K256FqNew().SetBytesWide(&r),
	}
}

func (s Secp256k1Scalar) CurveType() EccCurveType {
	return K256
}
func (s *Secp256k1Scalar) Add(lhs, rhs EccScalar) EccScalar {
	l := lhs.(*Secp256k1Scalar)
	r := rhs.(*Secp256k1Scalar)
	s.scalar.Add(l.scalar, r.scalar)
	return s
}

func (s *Secp256k1Scalar) Sub(lhs, rhs EccScalar) EccScalar {
	l := lhs.(*Secp256k1Scalar)
	r := rhs.(*Secp256k1Scalar)
	s.scalar.Sub(l.scalar, r.scalar)
	return s
}

func (s *Secp256k1Scalar) Mul(lhs, rhs EccScalar) EccScalar {
	l := lhs.(*Secp256k1Scalar)
	r := rhs.(*Secp256k1Scalar)
	s.scalar.Mul(l.scalar, r.scalar)
	return s
}

func (s *Secp256k1Scalar) Invert(other EccScalar) EccScalar {
	o := other.(*Secp256k1Scalar)
	s.scalar.Invert(o.scalar)
	return s
}

func (s *Secp256k1Scalar) Negate(other EccScalar) EccScalar {
	o := other.(*Secp256k1Scalar)
	s.scalar.Neg(o.scalar)
	return s
}

func (s *Secp256k1Scalar) Equal(other EccScalar) int {
	o := other.(*Secp256k1Scalar)

	return s.scalar.Equal(o.scalar)
}
func (s *Secp256k1Scalar) Assign(other EccScalar) EccScalar {
	o := other.(*Secp256k1Scalar)
	s.scalar.Set(o.scalar)
	return s
}

func (s *Secp256k1Scalar) Clone() EccScalar {
	return K256Scalar.Zero().Assign(s)
}

func (s Secp256k1Scalar) Serialize() []byte {
	bytes := s.scalar.Bytes()
	return common.ReverseBytes(bytes[:])
}

func (s Secp256k1Scalar) SerializeTagged() []byte {
	var bytes []byte
	bytes = append(bytes, []byte{byte(s.CurveType())}...)
	bytes = append(bytes, s.Serialize()...)
	return bytes
}

func (s Secp256k1Scalar) IsZero() int {
	return s.scalar.IsZero()
}

func (s Secp256k1Scalar) IsHigh() bool {
	return s.scalar.Cmp(OrderHalf) > 0
	return true
}
func (s Secp256k1Scalar) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(s.SerializeTagged())
}

func (s *Secp256k1Scalar) UnmarshalCBOR(data []byte) error {
	var bytes []byte
	if err := cbor.Unmarshal(data, &bytes); err != nil {
		return err
	}
	tmp, err := K256Scalar.Deserialize(bytes[1:])
	if err != nil {
		return err
	}
	s.scalar = tmp.scalar
	return nil
}
func (s Secp256k1Scalar) BigInt() *big.Int {
	return s.scalar.BigInt()
}

type Secp256K1ScalarBytes [32]byte

func (Secp256K1ScalarBytes) CurveType() EccCurveType {
	return K256
}
func (s Secp256K1ScalarBytes) ScalarBytes() []byte {
	return s[:]
}

func (s Secp256K1ScalarBytes) ToScalar() EccScalar {
	scalar, err := K256Scalar.Deserialize(s[:])
	if err != nil {
		panic(err.Error())
	}
	return scalar
}
