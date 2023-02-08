package dealings

import (
	"github.com/TraceBundy/tecdsa/curve"
	"github.com/TraceBundy/tecdsa/poly"
	"github.com/pkg/errors"
)

const (
	RandomSecretShare              = SecretShareType(0)
	ReshareOfUnmaskedSecretShare   = SecretShareType(1)
	ReshareOfMaskedSecretShare     = SecretShareType(2)
	UnmaskedTimesMaskedSecretShare = SecretShareType(3)
)

var (
	Secret = secretShares{}
)

type SecretShareType int

type SecretShares interface{}
type secretShares struct {
}

type RandomSecret struct{}
type ReshareOfUnmaskedSecret struct {
	S1 curve.EccScalar
}
type ReshareOfMaskedSecret struct {
	S1 curve.EccScalar
	S2 curve.EccScalar
}
type UnmaskedTimesMaskedSecret struct {
	Left  curve.EccScalar
	Right [2]curve.EccScalar
}

func (secretShares) From(cob1 poly.CommitmentOpeningBytes, cob2 poly.CommitmentOpeningBytes) (SecretShares, error) {
	var share SecretShares
	switch cm1 := cob1.(type) {
	case *poly.SimpleCommitmentOpeningBytes:
		if cob2 == nil {
			share = ReshareOfUnmaskedSecret{S1: cm1[0].ToScalar()}
		} else {
			if p, ok := cob2.(*poly.PedersenCommitmentOpeningBytes); ok {
				s1 := cm1[0].ToScalar()
				s2 := p[0].ToScalar()
				s3 := p[1].ToScalar()
				share = &UnmaskedTimesMaskedSecret{
					Left:  s1,
					Right: [2]curve.EccScalar{s2, s3},
				}
			} else {
				return nil, errors.New("inconsistent combination of commitment types")
			}
		}
	case *poly.PedersenCommitmentOpeningBytes:
		if cob2 != nil {
			return nil, errors.New("inconsistent combination of commitment types")
		}
		share = &ReshareOfMaskedSecret{S1: cm1[0].ToScalar(), S2: cm1[1].ToScalar()}
	}
	return share, nil
}
