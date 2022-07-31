package mega

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/rand"
	"github.com/PlatONnetwork/tecdsa/seed"
	"go.dedis.ch/kyber/v3"
)

const (
	Single = iota
	Pairs
)

type MEGaCiphertextType int

func (m MEGaCiphertextType) EncryptionDomainSep() string {
	switch m {
	case Single:
		return "ic-crypto-tecdsa-mega-encryption-single-encrypt"
	case Pairs:
		return "ic-crypto-tecdsa-mega-encryption-pair-encrypt"
	}
	return ""
}

func (m MEGaCiphertextType) PopBaseDomainSep() string {
	switch m {
	case Single:
		return "ic-crypto-tecdsa-mega-encryption-single-pop-base"
	case Pairs:
		return "ic-crypto-tecdsa-mega-encryption-pair-pop-base"
	}
	return ""
}

func (m MEGaCiphertextType) PopProofDomainSep() string {
	switch m {
	case Single:
		return "ic-crypto-tecdsa-mega-encryption-single-pop-proof"
	case Pairs:
		return "ic-crypto-tecdsa-mega-encryption-pair-pop-proof"
	}
	return ""
}

func (m MEGaCiphertextType) EphemeralKeyDomainSep() string {
	switch m {
	case Single:
		return "ic-crypto-tecdsa-mega-encryption-single-ephemeral-key"
	case Pairs:
		return "ic-crypto-tecdsa-mega-encryption-pair-ephemeral-key"
	}
	return ""
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

type MEGaPrivateKey struct {
	secret curve.EccScalar
}

func NewMEGaPrivateKey(secret curve.EccScalar) *MEGaPrivateKey {
	return &MEGaPrivateKey{
		secret: secret,
	}
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

func ComputeEphKeyAndPop(ctype MEGaCiphertextType, seed *seed.Seed, ad []byte, dealerIndex common.NodeIndex) {
}

func ComputePopBase(ctype MEGaCiphertextType, ad []byte, dealerIndex common.NodeIndex, ephemeralKey kyber.Point) {

}
