package mega

import (
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/rand"
	"github.com/PlatONnetwork/tecdsa/seed"
)

var (
	PublicKey  = mEGaPublicKey{}
	PrivateKey = mEGaPrivateKey{}
)

func GenKeypair(curveType curve.EccCurveType, seed *seed.Seed) (*MEGaPublicKey, *MEGaPrivateKey, error) {
	rng := seed.Rng()
	privateKey := PrivateKey.GeneratePrivateKey(curveType, rng)
	publicKey := privateKey.PublicKey()
	return publicKey, privateKey, nil
}

func VerifyMegaPublicKey(curveType curve.EccCurveType, raw []byte) error {
	_, err := PublicKey.Deserialize(curveType, raw)
	return err
}

type MEGaPublicKey struct {
	point curve.EccPoint
}

type mEGaPublicKey struct {
}

func (mEGaPublicKey) Deserialize(curveType curve.EccCurveType, value []byte) (*MEGaPublicKey, error) {
	point, err := curve.Point.Deserialize(curveType, value)
	if err != nil {
		return nil, err
	}
	return &MEGaPublicKey{point: point}, nil
}

func NewMEGaPublicKey(point curve.EccPoint) *MEGaPublicKey {
	return &MEGaPublicKey{
		point: point,
	}
}

func (m MEGaPublicKey) Serialize() []byte {
	return m.point.Serialize()
}

func (m MEGaPublicKey) PublicPoint() curve.EccPoint {
	return m.point
}

func (m MEGaPublicKey) CurveType() curve.EccCurveType {
	return m.point.CurveType()
}

type MEGaPrivateKey struct {
	secret curve.EccScalar
}

func NewMEGaPrivateKey(secret curve.EccScalar) *MEGaPrivateKey {
	return &MEGaPrivateKey{
		secret: secret,
	}
}
func (m MEGaPrivateKey) CurveType() curve.EccCurveType {
	return m.secret.CurveType()
}
func (m MEGaPrivateKey) PublicKey() *MEGaPublicKey {
	return NewMEGaPublicKey(curve.Point.MulByG(m.secret))
}

type mEGaPrivateKey struct {
}

func (mEGaPrivateKey) GeneratePrivateKey(curveType curve.EccCurveType, rng rand.Rand) *MEGaPrivateKey {
	secret := curve.Scalar.Random(curveType, rng)
	return &MEGaPrivateKey{
		secret: secret,
	}
}

func (mEGaPrivateKey) Deserialize(curveType curve.EccCurveType, value []byte) (*MEGaPrivateKey, error) {
	secret, err := curve.Scalar.Deserialize(curveType, value)
	if err != nil {
		return nil, err
	}
	return &MEGaPrivateKey{
		secret: secret,
	}, nil
}

func (m MEGaPrivateKey) Serialize() []byte {
	return m.secret.Serialize()
}

func (m MEGaPrivateKey) SecretScalar() curve.EccScalar {
	return m.secret
}
