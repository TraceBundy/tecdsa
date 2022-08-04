package dealings

import (
	"github.com/PlatONnetwork/tecdsa/poly"
)

type CombinedCommitment interface {
	poly.PolynomialCommitment
	Serialize() ([]byte, error)
}

type SummationCommitment struct {
	poly.PolynomialCommitment
}

func (s SummationCommitment) Serialize() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

type InterpolationCommitment struct {
	poly.PolynomialCommitment
}

func (i InterpolationCommitment) Serialize() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}
