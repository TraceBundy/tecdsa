package dealings

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/poly"
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

func CombineCommitmentsViaInterpolation(commitmentType poly.PolynomialCommitmentType, curveType curve.EccCurveType, reconstructionThreshold int, verifiedDealings btree.Map[common.NodeIndex, IDkgDealingInternal]) (CombinedCommitment, error) {
	commitments := make([]poly.PolynomialCommitment, verifiedDealings.Len(), verifiedDealings.Len())
	indexes := make([]uint32, verifiedDealings.Len(), verifiedDealings.Len())
	verifiedDealings.Scan(func(index common.NodeIndex, dealing *IDkgDealingInternal) {})
}
