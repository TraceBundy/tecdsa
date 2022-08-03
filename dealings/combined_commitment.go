package dealings

import "github.com/PlatONnetwork/tecdsa/poly"

type CombinedCommitment interface {
	Serialize() ([]byte, error)
}

type SummationCommitment struct {
	Commitment *poly.PolynomialCommitment
}

func (s SummationCommitment) Serialize() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

type InterpolationCommitment struct {
	Commitment *poly.PolynomialCommitment
}

func (i InterpolationCommitment) Serialize() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}
