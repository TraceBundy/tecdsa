package curve

import (
	"encoding/hex"
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/coinbase/kryptology/pkg/core/curves/native"
	"github.com/coinbase/kryptology/pkg/core/curves/native/k256/fp"
	"math/big"
)

var (
	K256Field = EccK256Field{}
)

type EccK256Field struct{}

type Secp256k1Field struct {
	field *native.Field
}

func fromHex(s string) *big.Int {
	r, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex in source file: " + s)
	}
	return r
}
func (e EccK256Field) FromHex(h string) *Secp256k1Field {
	bytes, err := hex.DecodeString(h)
	if err != nil {
		panic(err.Error())
	}
	return &Secp256k1Field{field: fp.K256FpNew().SetBigInt(new(big.Int).SetBytes(bytes))}
}
func (EccK256Field) FromBytes(bytes []byte) (*Secp256k1Field, error) {
	var r [32]byte
	copy(r[:], common.ReverseBytes(bytes[:]))
	field, err := fp.K256FpNew().SetBytes(&r)
	if err != nil {
		return nil, err
	}
	return &Secp256k1Field{
		field: field,
	}, nil
}

func (EccK256Field) FromBytesWide(bytes []byte) *Secp256k1Field {
	var r [64]byte
	copy(r[:], common.ReverseBytes(bytes[:]))
	field := fp.K256FpNew().SetBytesWide(&r)
	return &Secp256k1Field{
		field: field,
	}
}

func (EccK256Field) newField(b *big.Int) *Secp256k1Field {
	return &Secp256k1Field{
		field: fp.K256FpNew().SetBigInt(b),
	}
}

func (EccK256Field) Zero() *Secp256k1Field {
	return &Secp256k1Field{field: fp.K256FpNew().SetZero()}
}

func (EccK256Field) One() *Secp256k1Field {
	return &Secp256k1Field{field: fp.K256FpNew().SetOne()}
}

func (k EccK256Field) FieldA() *Secp256k1Field {
	return k.newField(big.NewInt(0))
}
func (k EccK256Field) FieldB() *Secp256k1Field {
	return k.newField(fromHex("0000000000000000000000000000000000000000000000000000000000000007"))
}
func (k EccK256Field) FieldSswuA() *Secp256k1Field {
	return k.newField(fromHex("3F8731ABDD661ADCA08A5558F0F5D272E953D363CB6F0E5D405447C01A444533"))
}
func (k EccK256Field) FieldSswuB() *Secp256k1Field {
	return k.newField(fromHex("00000000000000000000000000000000000000000000000000000000000006eb"))
}
func (k EccK256Field) FieldSswuZ() *Secp256k1Field {
	return k.newField(fromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc24"))
}
func (k EccK256Field) FieldSswuC2() *Secp256k1Field {
	return k.newField(fromHex("31fdf302724013e57ad13fb38f842afeec184f00a74789dd286729c8303c4a59"))
}

func (s Secp256k1Field) CurveType() EccCurveType {
	return K256
}

func (s *Secp256k1Field) Clone() EccFieldElement {
	return K256Field.Zero().Assign(s)
}

func (s *Secp256k1Field) Assign(other EccFieldElement) EccFieldElement {
	s.field.Set(other.(*Secp256k1Field).field)
	return s
}

func (s *Secp256k1Field) Add(lhs, rhs EccFieldElement) EccFieldElement {
	l := lhs.(*Secp256k1Field)
	r := rhs.(*Secp256k1Field)
	s.field.Add(l.field, r.field)
	return s
}

func (s *Secp256k1Field) Sub(lhs, rhs EccFieldElement) EccFieldElement {
	l := lhs.(*Secp256k1Field)
	r := rhs.(*Secp256k1Field)
	s.field.Sub(l.field, r.field)
	return s
}
func (s *Secp256k1Field) Mul(lhs, rhs EccFieldElement) EccFieldElement {
	l := lhs.(*Secp256k1Field)
	r := rhs.(*Secp256k1Field)
	s.field.Mul(l.field, r.field)
	return s
}

func (s *Secp256k1Field) Square(other EccFieldElement) EccFieldElement {
	s.field.Square(other.(*Secp256k1Field).field)
	return s
}

func (s Secp256k1Field) Equal(other EccFieldElement) int {
	return s.field.Equal(other.(*Secp256k1Field).field)
}

func (s *Secp256k1Field) CAssign(other EccFieldElement, choice int) {
	s.field.CMove(s.field, other.(*Secp256k1Field).field, choice)
}

func (s *Secp256k1Field) Invert(other EccFieldElement) EccFieldElement {
	s.field.Invert(other.(*Secp256k1Field).field)
	return s
}

func (s *Secp256k1Field) Negate(other EccFieldElement) EccFieldElement {
	s.field.Neg(other.(*Secp256k1Field).field)
	return s
}

func (s *Secp256k1Field) Sqrt(other EccFieldElement) (EccFieldElement, int) {
	_, flag := s.field.Sqrt(other.(*Secp256k1Field).field)
	choice := 1
	if !flag {
		s.field.SetZero()
		choice = 0
	}
	return s, choice
}

func (s *Secp256k1Field) Progenitor(other EccFieldElement) EccFieldElement {
	m34 := new(big.Int).Sub(fp.K256FpNew().Params.BiModulus, big.NewInt(3))
	m34.Div(m34, big.NewInt(4))
	s.field.Exp(other.(*Secp256k1Field).field, fp.K256FpNew().SetBigInt(m34))
	return s
}

func (s Secp256k1Field) IsZero() int {
	return s.field.IsZero()
}

func (s Secp256k1Field) AsBytes() []byte {
	bytes := s.field.BigInt().Bytes()
	if len(bytes) > 32 {
		panic("field element longer than 256 bits")
	}
	var rv [32]byte
	copy(rv[32-len(bytes):], bytes) // leftpad w zeros
	return rv[:]
}

func (s Secp256k1Field) Sign() uint8 {
	bytes := s.field.Bytes()
	return common.ReverseBytes(bytes[:])[native.FieldBytes-1] & 1
}
func (s Secp256k1Field) BigInt() *big.Int {
	return s.field.BigInt()
}
