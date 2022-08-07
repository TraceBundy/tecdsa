package dealings

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/mega"
	"github.com/PlatONnetwork/tecdsa/poly"
	"github.com/pkg/errors"
	"github.com/tidwall/btree"
)

var (
	CommitmentOpening = commitmentOpening{}
)

type commitmentOpening struct {
}

func (c commitmentOpening) OpenDealing(verifiedDealing *IDkgDealingInternal, ad []byte, dealerIndex common.NodeIndex, openerIndex common.NodeIndex, openerSecretKey *mega.MEGaPrivateKey, openerPublicKey *mega.MEGaPublicKey) (poly.CommitmentOpening, error) {
	return verifiedDealing.Ciphertext.DecryptAndCheck(verifiedDealing.Commitment, ad, dealerIndex, openerIndex, openerSecretKey, openerPublicKey)

}
func (c commitmentOpening) FromDealingsAndOpenings(verifiedDealings *btree.Map[common.NodeIndex, *IDkgDealingInternal], providedOpenings *btree.Map[common.NodeIndex, *btree.Map[common.NodeIndex, poly.CommitmentOpening]], transcriptCommitment CombinedCommitment, contextData []byte, receiverIndex common.NodeIndex, secretKey *mega.MEGaPrivateKey, publicKey *mega.MEGaPublicKey) (poly.CommitmentOpening, error) {
	nodeIndexOpenings := make([]common.NodeIndex, 0, verifiedDealings.Len())
	commitmentOpenings := make([]poly.CommitmentOpening, 0, verifiedDealings.Len())
	var err error
	verifiedDealings.Scan(func(dealerIndex common.NodeIndex, dealing *IDkgDealingInternal) bool {
		var opening poly.CommitmentOpening
		if shares, ok := providedOpenings.Get(dealerIndex); ok {
			opening, err = ReconstructShareFromOpenings(dealing, shares, receiverIndex)
			if err != nil {
				return false
			}
		} else {
			if opening, err = dealing.Ciphertext.DecryptAndCheck(dealing.Commitment, contextData, dealerIndex, receiverIndex, secretKey, publicKey); err != nil {
				return false
			}
		}
		nodeIndexOpenings = append(nodeIndexOpenings, dealerIndex)
		commitmentOpenings = append(commitmentOpenings, opening)
		return true
	})
	if err != nil {
		return nil, err
	}
	return c.CombineOpenings(nodeIndexOpenings, commitmentOpenings, transcriptCommitment, receiverIndex, secretKey.CurveType())
}
func (c commitmentOpening) FromDealings(verifiedDealings *btree.Map[common.NodeIndex, *IDkgDealingInternal], transcriptCommitment CombinedCommitment, contextData []byte, receiverIndex common.NodeIndex, secretKey *mega.MEGaPrivateKey, publicKey *mega.MEGaPublicKey) (poly.CommitmentOpening, error) {
	nodeIndexOpenings := make([]common.NodeIndex, 0, verifiedDealings.Len())
	commitmentOpenings := make([]poly.CommitmentOpening, 0, verifiedDealings.Len())
	var err error
	verifiedDealings.Scan(func(dealerIndex common.NodeIndex, dealing *IDkgDealingInternal) bool {
		var opening poly.CommitmentOpening
		if opening, err = dealing.Ciphertext.DecryptAndCheck(dealing.Commitment, contextData, dealerIndex, receiverIndex, secretKey, publicKey); err != nil {
			return false
		}

		nodeIndexOpenings = append(nodeIndexOpenings, dealerIndex)
		commitmentOpenings = append(commitmentOpenings, opening)
		return true
	})
	if err != nil {
		return nil, err
	}
	return c.CombineOpenings(nodeIndexOpenings, commitmentOpenings, transcriptCommitment, receiverIndex, secretKey.CurveType())

}

func (commitmentOpening) CombineOpenings(nodeIndexOpenings []common.NodeIndex, commitmentOpenings []poly.CommitmentOpening, transcriptCommitment CombinedCommitment, receiverIndex common.NodeIndex, curveType curve.EccCurveType) (poly.CommitmentOpening, error) {
	var opening poly.CommitmentOpening

	switch t := transcriptCommitment.(type) {
	case *SummationCommitment:
		combinedValue := curve.Scalar.Zero(curveType)
		combinedMask := curve.Scalar.Zero(curveType)
		for _, opening := range commitmentOpenings {
			switch o := opening.(type) {
			case poly.PedersenCommitmentOpening:
				combinedValue = combinedValue.Add(combinedValue, o[0])
				combinedMask = combinedMask.Add(combinedMask, o[1])
			default:
				return nil, errors.New("unexpected commitment type")
			}
		}
		opening = poly.PedersenCommitmentOpening([2]curve.EccScalar{combinedValue, combinedMask})
	case *InterpolationCommitment:
		switch t.PolynomialCommitment.(type) {
		case *poly.SimpleCommitment:
			xValues := make([]common.NodeIndex, 0, len(commitmentOpenings))
			values := make([]curve.EccScalar, 0, len(commitmentOpenings))
			for i := 0; i < len(commitmentOpenings); i++ {
				dealerIndex, opening := nodeIndexOpenings[i], commitmentOpenings[i]
				switch o := opening.(type) {
				case poly.SimpleCommitmentOpening:
					xValues = append(xValues, dealerIndex)
					values = append(values, o[0])
				default:
					return nil, errors.New("unexpected commitment type")
				}
			}

			coefficients, err := poly.Lagrange.AtZero(curveType, xValues)
			if err != nil {
				return nil, err
			}
			combinedValue, err := coefficients.InterpolateScalar(values)
			if err != nil {
				return nil, err
			}
			opening = poly.SimpleCommitmentOpening{combinedValue}

		case *poly.PedersenCommitment:
			xValues := make([]common.NodeIndex, 0, len(commitmentOpenings))
			values := make([]curve.EccScalar, 0, len(commitmentOpenings))
			masks := make([]curve.EccScalar, 0, len(commitmentOpenings))
			for i := 0; i < len(commitmentOpenings); i++ {
				dealerIndex, opening := nodeIndexOpenings[i], commitmentOpenings[i]
				switch o := opening.(type) {
				case poly.PedersenCommitmentOpening:
					xValues = append(xValues, dealerIndex)
					values = append(values, o[0])
					masks = append(masks, o[1])
				default:
					return nil, errors.New("unexpected commitment type")
				}
			}
			coefficients, err := poly.Lagrange.AtZero(curveType, xValues)
			if err != nil {
				return nil, err
			}
			combinedValue, err := coefficients.InterpolateScalar(values)
			if err != nil {
				return nil, err
			}
			combinedMask, err := coefficients.InterpolateScalar(masks)
			if err != nil {
				return nil, err
			}
			opening = poly.PedersenCommitmentOpening([2]curve.EccScalar{combinedValue, combinedMask})
		}
	}
	return transcriptCommitment.ReturnOpeningIfConsistent(receiverIndex, opening)
}
