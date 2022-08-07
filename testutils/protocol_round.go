package testutils

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/dealings"
	"github.com/PlatONnetwork/tecdsa/poly"
	"github.com/pkg/errors"
	"github.com/tidwall/btree"
)

var (
	Round = protocolRound{}
)

type ProtocolRound struct {
	Commitment poly.PolynomialCommitment
	Transcript *dealings.IDkgTranscriptInternal
	Openings   []poly.CommitmentOpening
	Dealings   *btree.Map[common.NodeIndex, *dealings.IDkgDealingInternal]
}

type protocolRound struct {
}

func (p protocolRound) New(setup *ProtocolSetup, dealings *btree.Map[common.NodeIndex, *dealings.IDkgDealingInternal], transcript *dealings.IDkgTranscriptInternal) (*ProtocolRound, error) {
	openings, err := OpenDealings(setup, dealings, transcript)
	if err != nil {
		return nil, err
	}
	commitment := transcript.CombinedCommitment.Clone()
	return &ProtocolRound{
		commitment,
		transcript,
		openings,
		dealings,
	}, nil
}

func (p protocolRound) VerifyCommitmentOpenings(commitment poly.PolynomialCommitment, openings []poly.CommitmentOpening) error {
	constantTerm := commitment.ConstantTerm()
	curveType := constantTerm.CurveType()

	if _, ok := commitment.(*poly.SimpleCommitment); ok {
		indexes := make([]common.NodeIndex, 0, len(openings))
		gopenings := make([]curve.EccScalar, 0, len(openings))
		for idx, opening := range openings {
			if o, ok := opening.(poly.SimpleCommitmentOpening); ok {
				indexes = append(indexes, common.NodeIndex(idx))
				gopenings = append(gopenings, o[0])
			}
		}
		coefficients, err := poly.Lagrange.AtZero(curveType, indexes)
		if err != nil {
			return err
		}
		dlog, err := coefficients.InterpolateScalar(gopenings)
		if err != nil {
			return err
		}
		pt := curve.Point.MulByG(dlog)
		if pt.Equal(constantTerm) == 0 {
			return errors.New("verify failed")
		}
	} else {
		indexes := make([]common.NodeIndex, 0, len(openings))
		gopenings := make([]curve.EccScalar, 0, len(openings))
		hopenings := make([]curve.EccScalar, 0, len(openings))
		for idx, opening := range openings {
			if o, ok := opening.(poly.PedersenCommitmentOpening); ok {
				indexes = append(indexes, common.NodeIndex(idx))
				gopenings = append(gopenings, o[0])
				hopenings = append(hopenings, o[1])
			}
		}
		coefficients, err := poly.Lagrange.AtZero(curveType, indexes)
		if err != nil {
			return err
		}
		dlogg, err := coefficients.InterpolateScalar(gopenings)
		if err != nil {
			return err
		}
		dlogh, err := coefficients.InterpolateScalar(hopenings)
		if err != nil {
			return err
		}
		pt := curve.Point.Pedersen(dlogg, dlogh)
		if pt.Equal(constantTerm) == 0 {
			return errors.New("verify failed")
		}
	}
	return nil
}
