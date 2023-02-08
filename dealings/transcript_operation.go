package dealings

import (
	"bytes"
	"github.com/TraceBundy/tecdsa/common"
	"github.com/TraceBundy/tecdsa/curve"
)

type IDkgTranscriptInternal struct {
	CombinedCommitment CombinedCommitment
}

func (t IDkgTranscriptInternal) ConstantTerm() curve.EccPoint {
	return t.CombinedCommitment.ConstantTerm()
}
func (t IDkgTranscriptInternal) EvaluateAt(evalPoint common.NodeIndex) curve.EccPoint {
	return t.CombinedCommitment.EvaluateAt(evalPoint)
}
func (t IDkgTranscriptInternal) Compare(other IDkgTranscriptInternal) int {
	lhs := t.CombinedCommitment.StableRepresentation()
	rhs := t.CombinedCommitment.StableRepresentation()
	return bytes.Compare(lhs, rhs)
}
