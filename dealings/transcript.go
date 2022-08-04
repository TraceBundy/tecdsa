package dealings

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/poly"
	"github.com/pkg/errors"
	"github.com/tidwall/btree"
)

type IDkgTranscriptOperationInternal interface{}

type RandomTranscript struct{}
type ReshareOfUnmaskedTranscript struct {
	P1 poly.PolynomialCommitment
}
type ReshareOfMaskedTranscript struct {
	P1 poly.PolynomialCommitment
}
type UnmaskedTimesMaskedTranscript struct {
	Left  poly.PolynomialCommitment
	Right poly.PolynomialCommitment
}

func CombineCommitmentsViaInterpolation(commitmentType poly.PolynomialCommitmentType, curveType curve.EccCurveType, reconstructionThreshold int, verifiedDealings *btree.Map[common.NodeIndex, *IDkgDealingInternal]) (CombinedCommitment, error) {
	commitments := make([]poly.PolynomialCommitment, 0, verifiedDealings.Len())
	indexes := make([]common.NodeIndex, 0, verifiedDealings.Len())
	verifiedDealings.Scan(func(index common.NodeIndex, dealing *IDkgDealingInternal) bool {
		indexes = append(indexes, index)
		commitments = append(commitments, dealing.Commitment.Clone())
		return true
	})
	coefficients, err := poly.Lagrange.AtZero(curveType, indexes)
	if err != nil {
		return nil, err
	}
	combined := make([]curve.EccPoint, 0, reconstructionThreshold)
	for i := 0; i < reconstructionThreshold; i++ {
		values := make([]curve.EccPoint, 0, len(commitments))
		for _, commitment := range commitments {
			values = append(values, commitment.Points()[i])
		}
		point, err := coefficients.InterpolatePoint(values)
		if err != nil {
			return nil, err
		}
		combined = append(combined, point)
	}
	var cm poly.PolynomialCommitment
	switch commitmentType {
	case poly.Simple:
		cm = poly.SimpleCM.New(combined)
	case poly.Pedersen:
		cm = poly.PedersenCM.New(combined)
	}
	return InterpolationCommitment{cm}, nil
}

func NewTranscriptInternal(curveType curve.EccCurveType, reconstructionThreshold int, verifiedDealings *btree.Map[common.NodeIndex, *IDkgDealingInternal], operationMode IDkgTranscriptOperationInternal) (*IDkgTranscriptInternal, error) {
	for _, dealing := range verifiedDealings.Values() {
		if len(dealing.Commitment.Points()) != reconstructionThreshold {
			return nil, errors.New("unexpected commitment type")
		}
	}

	var combinedCommitment CombinedCommitment
	var err error

	switch o := operationMode.(type) {
	case *RandomTranscript:
		combined := make([]curve.EccPoint, reconstructionThreshold, reconstructionThreshold)
		for i := range combined {
			combined[i] = curve.Point.Identity(curveType)
		}
		for _, dealing := range verifiedDealings.Values() {
			if dealing.Commitment.Type() != poly.Pedersen {
				return nil, errors.New("unexpected commitment type")
			}
			c := dealing.Commitment.Points()
			for i := 0; i < reconstructionThreshold; i++ {
				combined[i] = combined[i].AddPoints(combined[i], c[i])
			}
		}
		combinedCommitment = SummationCommitment{poly.PedersenCM.New(combined)}
	case *ReshareOfMaskedTranscript:
		if o.P1.Type() != poly.Pedersen {
			return nil, errors.New("unexpected commitment type")
		}
		if verifiedDealings.Len() < len(o.P1.Points()) {
			return nil, errors.New("insufficient dealings")
		}
		combinedCommitment, err = CombineCommitmentsViaInterpolation(poly.Simple, curveType, reconstructionThreshold, verifiedDealings)
		if err != nil {
			return nil, err
		}
	case *ReshareOfUnmaskedTranscript:
		if o.P1.Type() != poly.Simple {
			return nil, errors.New("unexpected commitment type")
		}
		if verifiedDealings.Len() < len(o.P1.Points()) {
			return nil, errors.New("insufficient dealings")
		}
		combinedCommitment, err = CombineCommitmentsViaInterpolation(poly.Simple, curveType, reconstructionThreshold, verifiedDealings)
		if err != nil {
			return nil, err
		}
		if o.P1.Points()[0].Equal(combinedCommitment.Points()[0]) != 1 {
			return nil, errors.New("invalid commitment")
		}
	case *UnmaskedTimesMaskedTranscript:
		if o.Left.Type() != poly.Simple || o.Right.Type() != poly.Pedersen {
			return nil, errors.New("unexpected commitment type")
		}
		if verifiedDealings.Len() < len(o.Left.Points())+len(o.Right.Points())-1 {
			return nil, errors.New("insufficient dealings")
		}
		combinedCommitment, err = CombineCommitmentsViaInterpolation(poly.Pedersen, curveType, reconstructionThreshold, verifiedDealings)
		if err != nil {
			return nil, err
		}
	}
	return &IDkgTranscriptInternal{CombinedCommitment: combinedCommitment}, nil
}

/// Reconstruct a secret share from a set of openings
///
/// # Arguments:
/// * `dealing` for which we want to reconstruct the secret share.
/// * `openings` provided to compute the secret shares.
/// * `share_index` index of the receiver for which we are trying to recompute the secret share.
///
/// # Errors:
/// * `InsufficientOpenings` if the provided openings are insufficient
///   to reconstruct the share for the given share_index.
/// * `InconsistentCommitment` if the openings resulted in a share that
///   is not consistent with the dealing commitment.
/// * Any other error if the share could not be recomputed.
func ReconstructShareFromOpenings(dealing *IDkgDealingInternal, openings *btree.Map[common.NodeIndex, poly.CommitmentOpening], shareIndex common.NodeIndex) (poly.CommitmentOpening, error) {
	reconstructionThreshold := dealing.Commitment.Len()
	if openings.Len() < reconstructionThreshold {
		return nil, errors.New("insufficient openings")
	}
	curveType := dealing.Commitment.CurveType()
	index := curve.Scalar.FromNodeIndex(curveType, shareIndex)
	var commitmentOpening poly.CommitmentOpening
	var err error
	switch dealing.Commitment.(type) {
	case *poly.SimpleCommitment:
		xValues := make([]common.NodeIndex, 0, openings.Len())
		values := make([]curve.EccScalar, 0, openings.Len())
		openings.Scan(func(receiverIndex common.NodeIndex, opening poly.CommitmentOpening) bool {
			switch o := opening.(type) {
			case poly.SimpleCommitmentOpening:
				xValues = append(xValues, receiverIndex)
				values = append(values, o[0])
			case poly.PedersenCommitmentOpening:
				err = errors.New("unexpected commitment type")
				return false
			}
			return true
		})
		if err != nil {
			return nil, err
		}
		coefficients, err := poly.Lagrange.AtValue(index, xValues)
		if err != nil {
			return nil, err
		}
		combinedValue, err := coefficients.InterpolateScalar(values)
		if err != nil {
			return nil, err
		}
		commitmentOpening = &poly.SimpleCommitmentOpening{combinedValue}
	case *poly.PedersenCommitment:
		xValues := make([]common.NodeIndex, 0, openings.Len())
		values := make([]curve.EccScalar, 0, openings.Len())
		masks := make([]curve.EccScalar, 0, openings.Len())
		openings.Scan(func(receiverIndex common.NodeIndex, opening poly.CommitmentOpening) bool {
			switch o := opening.(type) {
			case poly.PedersenCommitmentOpening:
				xValues = append(xValues, receiverIndex)
				values = append(values, o[0])
				masks = append(masks, o[1])
			case poly.SimpleCommitmentOpening:
				err = errors.New("unexpected commitment type")
				return false
			}
			return true
		})
		if err != nil {
			return nil, err
		}
		var coeffcients *poly.LagrangeCoefficients
		var combinedValue curve.EccScalar
		var combinedMask curve.EccScalar
		if coeffcients, err = poly.Lagrange.AtValue(index, xValues); err != nil {
			return nil, err
		}
		if combinedValue, err = coeffcients.InterpolateScalar(values); err != nil {
			return nil, err
		}
		if combinedMask, err = coeffcients.InterpolateScalar(masks); err != nil {
			return nil, err
		}
		commitmentOpening = &poly.PedersenCommitmentOpening{combinedValue, combinedMask}
	}
	return dealing.Commitment.ReturnOpeningIfConsistent(shareIndex, commitmentOpening)
}
