package testutils

import (
	"github.com/TraceBundy/tecdsa/common"
	"github.com/TraceBundy/tecdsa/curve"
	"github.com/TraceBundy/tecdsa/dealings"
	"github.com/TraceBundy/tecdsa/poly"
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

func (p ProtocolRound) ConstantTerm() curve.EccPoint {
	return p.Commitment.ConstantTerm()
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

func (p protocolRound) Random(setup *ProtocolSetup, numberOfDealers int, numberOfDealingsCorrupted int) (*ProtocolRound, error) {
	shares := make([]dealings.SecretShares, numberOfDealers, numberOfDealers)
	for i, _ := range shares {
		shares[i] = &dealings.RandomSecret{}
	}
	mode := &dealings.RandomTranscript{}
	dealings, err := CreateDealings(setup, shares, numberOfDealers, numberOfDealingsCorrupted, mode, setup.NextDealingSeed())
	if err != nil {
		return nil, err
	}
	transcript, err := CreateTranscript(setup, dealings, mode)
	if err != nil {
		return nil, err
	}
	return p.New(setup, dealings, transcript)
}
func (p protocolRound) ReshareOfMasked(setup *ProtocolSetup, masked *ProtocolRound, numberOfDealers int, numberOfDealingsCorrupted int) (*ProtocolRound, error) {
	shares := make([]dealings.SecretShares, len(masked.Openings), len(masked.Openings))
	for i, opening := range masked.Openings {
		if o, ok := opening.(poly.PedersenCommitmentOpening); ok {
			shares[i] = &dealings.ReshareOfMaskedSecret{S1: o[0], S2: o[1]}
		} else {
			panic("unexpected opening type")
		}
	}
	mode := &dealings.ReshareOfMaskedTranscript{P1: masked.Commitment.Clone()}
	dealings, err := CreateDealings(setup, shares, numberOfDealers, numberOfDealingsCorrupted, mode, setup.NextDealingSeed())
	if err != nil {
		return nil, err
	}

	transcript, err := CreateTranscript(setup, dealings, mode)
	if err != nil {
		return nil, err
	}

	return p.New(setup, dealings, transcript)
}

func (p protocolRound) ReshareOfUnmasked(setup *ProtocolSetup, unmasked *ProtocolRound, numberOfDealers int, numberOfDealingsCorrupted int) (*ProtocolRound, error) {
	shares := make([]dealings.SecretShares, len(unmasked.Openings))
	for i, opening := range unmasked.Openings {
		if o, ok := opening.(poly.SimpleCommitmentOpening); ok {
			shares[i] = &dealings.ReshareOfUnmaskedSecret{S1: o[0]}
		} else {
			panic("unexpected opening type")
		}
	}
	mode := &dealings.ReshareOfUnmaskedTranscript{P1: unmasked.Commitment.Clone()}
	dealings, err := CreateDealings(setup, shares, numberOfDealers, numberOfDealingsCorrupted, mode, setup.NextDealingSeed())
	if err != nil {
		return nil, err
	}
	transcript, err := CreateTranscript(setup, dealings, mode)
	if err != nil {
		return nil, err
	}
	return p.New(setup, dealings, transcript)
}

func (p protocolRound) Multiply(setup *ProtocolSetup, masked *ProtocolRound, unmasked *ProtocolRound, numberOfDealers int, numberOfDealingsCorrupted int) (*ProtocolRound, error) {
	shares := make([]dealings.SecretShares, len(unmasked.Openings))
	for i, opening := range unmasked.Openings {
		if o, ok := opening.(poly.SimpleCommitmentOpening); ok {
			p, ok := masked.Openings[i].(poly.PedersenCommitmentOpening)
			if !ok {
				panic("unexpected opening type")
			}
			shares[i] = &dealings.UnmaskedTimesMaskedSecret{Left: o[0], Right: p}
		} else {
			panic("unexpected opening type")
		}
	}
	mode := &dealings.UnmaskedTimesMaskedTranscript{Left: unmasked.Commitment.Clone(), Right: masked.Commitment.Clone()}
	dealings, err := CreateDealings(setup, shares, numberOfDealers, numberOfDealingsCorrupted, mode, setup.NextDealingSeed())
	if err != nil {
		return nil, err
	}
	transcript, err := CreateTranscript(setup, dealings, mode)
	if err != nil {
		return nil, err
	}
	return p.New(setup, dealings, transcript)
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
