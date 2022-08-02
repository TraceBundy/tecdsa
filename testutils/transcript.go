package testutils

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	dealings2 "github.com/PlatONnetwork/tecdsa/dealings"
	"github.com/tidwall/btree"
)

func CreateTranscript(setup *ProtocolSetup, dealings *btree.Map[common.NodeIndex, *dealings2.IDkgDealingInternal], mode dealings2.IDkgTranscriptOperationInternal) (*dealings2.IDkgTranscriptInternal, error) {
	return dealings2.NewTranscriptInternal(curve.K256, setup.Threshold, dealings, mode)
}
