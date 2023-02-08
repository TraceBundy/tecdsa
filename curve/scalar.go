package curve

import (
	"github.com/TraceBundy/tecdsa/common"
	"github.com/TraceBundy/tecdsa/rand"
	"github.com/TraceBundy/tecdsa/seed"
	"github.com/pkg/errors"
	"math/big"
)

var (
	Scalar = scalar{}
)

type scalar struct{}

type EccScalar interface {
	CurveType() EccCurveType
	Add(lhs, rhs EccScalar) EccScalar
	Sub(lhs, rhs EccScalar) EccScalar
	Mul(lhs, rhs EccScalar) EccScalar
	Invert(other EccScalar) EccScalar
	Negate(other EccScalar) EccScalar
	Assign(other EccScalar) EccScalar
	Clone() EccScalar
	Equal(other EccScalar) int
	IsZero() int
	IsHigh() bool
	BigInt() *big.Int
	Serialize() []byte
	SerializeTagged() []byte
}

func (s scalar) HashToScalar(curve EccCurveType, input []byte, domainSeparator []byte) (EccScalar, error) {
	h, err := HashToScalar(1, curve, input, domainSeparator)
	if err != nil {
		return nil, err
	}
	return h[0], nil
}

func (s scalar) HashToSeveralScalar(curve EccCurveType, count int, input []byte, domainSeparator []byte) ([]EccScalar, error) {
	return HashToScalar(count, curve, input, domainSeparator)
}

func (s scalar) DeserializeTagged(bytes []byte) (EccScalar, error) {
	if len(bytes) == 0 {
		return nil, errors.New("invalid scalar")
	}
	var scalar EccScalar
	var err error
	switch EccCurveType(bytes[0]) {
	case K256:
		scalar, err = K256Scalar.Deserialize(bytes[0:])

	}
	return scalar, err
}

func (s scalar) Deserialize(curve EccCurveType, bytes []byte) (EccScalar, error) {
	if len(bytes) == 0 {
		return nil, errors.New("invalid scalar")
	}
	var scalar EccScalar
	var err error
	switch curve {
	case K256:
		scalar, err = K256Scalar.Deserialize(bytes)
	}
	return scalar, err
}

func (s scalar) FromBytesWide(curve EccCurveType, bytes []byte) (EccScalar, error) {
	var scalar EccScalar
	switch curve {
	case K256:
		scalar = K256Scalar.FromWideBytes(bytes)

	}
	return scalar, nil
}

func (s scalar) Zero(curve EccCurveType) EccScalar {
	var scalar EccScalar
	switch curve {
	case K256:
		scalar = K256Scalar.Zero()
	}
	return scalar
}

func (s scalar) One(curve EccCurveType) EccScalar {
	var scalar EccScalar
	switch curve {
	case K256:
		scalar = K256Scalar.One()
	}
	return scalar
}

func (s scalar) Random(curve EccCurveType, rng rand.Rand) EccScalar {
	buf := make([]byte, curve.ScalarBytes())
	for {
		rng.FillUint8(buf)
		if scalar, err := s.Deserialize(curve, buf); err == nil {
			return scalar
		}
	}
}

func (s scalar) FromSeed(curve EccCurveType, seed *seed.Seed) EccScalar {
	rng := seed.Rng()
	return s.Random(curve, rng)
}

func (s scalar) ToScalarBytes(scalar EccScalar) EccScalarBytes {
	var bytes EccScalarBytes
	switch scalar.CurveType() {
	case K256:
		var k256 Secp256K1ScalarBytes
		copy(k256[:], scalar.Serialize())
	}
	return bytes
}

func (s scalar) FromUint64(curve EccCurveType, n uint64) EccScalar {
	var scalar EccScalar
	switch curve {
	case K256:
		scalar = K256Scalar.FromUint64(n)
	}
	return scalar
}

func (s scalar) FromNodeIndex(curve EccCurveType, index common.NodeIndex) EccScalar {
	return s.FromUint64(curve, uint64(index)+1)
}

type EccScalarBytes interface {
	CurveType() EccCurveType
	ScalarBytes() []byte
	ToScalar() EccScalar
}
