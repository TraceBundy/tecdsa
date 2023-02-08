package sign

import (
	"github.com/TraceBundy/tecdsa/common"
	"github.com/TraceBundy/tecdsa/curve"
	"github.com/TraceBundy/tecdsa/dealings"
	"github.com/TraceBundy/tecdsa/key"
	poly2 "github.com/TraceBundy/tecdsa/poly"
	"github.com/pkg/errors"
)

type ThresholdEcdsaSigShareInternal struct {
	sigmaNumerator   poly2.CommitmentOpening
	sigmaDenominator poly2.CommitmentOpening
}

func NewThresholdEcdsaSigShareInternal(derivationPath *key.DerivationPath, hashedMsg []byte, randomness []byte, keyTranscript *dealings.IDkgTranscriptInternal, presigTranscript *dealings.IDkgTranscriptInternal, lambda poly2.CommitmentOpening, kappaTimesLambda poly2.CommitmentOpening, keyTimesLambda poly2.CommitmentOpening, curveType curve.EccCurveType) (*ThresholdEcdsaSigShareInternal, error) {
	rho, keyTweak, randomizer, _, err := DeriveRho(curveType, hashedMsg, randomness, derivationPath, keyTranscript, presigTranscript)
	if err != nil {
		return nil, err
	}
	e, err := ConvertHashToInteger(hashedMsg, curveType)
	if err != nil {
		return nil, err
	}
	theta := e.Add(e, rho.Clone().Mul(rho, keyTweak))
	var lambdaValue curve.EccScalar
	var lambdaMask curve.EccScalar
	if l, ok := lambda.(poly2.PedersenCommitmentOpening); ok {
		lambdaValue = l[0]
		lambdaMask = l[1]
	}
	var nu poly2.CommitmentOpening
	if k, ok := keyTimesLambda.(poly2.PedersenCommitmentOpening); ok {
		nuValue := theta.Clone().Mul(theta, lambdaValue)
		nuValue = nuValue.Add(nuValue, rho.Clone().Mul(rho, k[0]))
		nuMask := theta.Clone().Mul(theta, lambdaMask)
		nuMask = nuMask.Add(nuMask, rho.Clone().Mul(rho, k[1]))
		nu = poly2.PedersenCommitmentOpening{nuValue, nuMask}
	}

	var mu poly2.CommitmentOpening
	if k, ok := kappaTimesLambda.(poly2.PedersenCommitmentOpening); ok {
		muValue := randomizer.Clone().Mul(randomizer, lambdaValue)
		muValue = muValue.Add(muValue, k[0])
		muMask := randomizer.Clone().Mul(randomizer, lambdaMask)
		muMask = muMask.Add(muMask, k[1])
		mu = poly2.PedersenCommitmentOpening{muValue, muMask}
	}
	return &ThresholdEcdsaSigShareInternal{
		sigmaNumerator:   nu,
		sigmaDenominator: mu,
	}, nil
}

func (t ThresholdEcdsaSigShareInternal) Verify(derivationPath *key.DerivationPath, hashedMsg []byte, randomness []byte, signerIndex common.NodeIndex, keyTranscript *dealings.IDkgTranscriptInternal, presigTranscript *dealings.IDkgTranscriptInternal, lambda *dealings.IDkgTranscriptInternal, kappaTimesLambda *dealings.IDkgTranscriptInternal, keyTimesLambda *dealings.IDkgTranscriptInternal, curveType curve.EccCurveType) error {
	rho, keyTweak, randomizer, _, err := DeriveRho(curveType, hashedMsg, randomness, derivationPath, keyTranscript, presigTranscript)
	if err != nil {
		return err
	}

	e, err := ConvertHashToInteger(hashedMsg, curveType)
	if err != nil {
		return err
	}
	theta := e.Add(e, rho.Clone().Mul(rho, keyTweak))

	lambdaj := lambda.EvaluateAt(signerIndex)
	kappaTimesLambdaJ := kappaTimesLambda.EvaluateAt(signerIndex)
	keyTimesLambdaJ := keyTimesLambda.EvaluateAt(signerIndex)
	sigmaNum := lambdaj.Clone().ScalarMul(lambdaj, theta)
	sigmaNum = sigmaNum.AddPoints(sigmaNum, keyTimesLambdaJ.Clone().ScalarMul(kappaTimesLambdaJ, rho))
	sigmaDen := lambdaj.Clone().ScalarMul(lambdaj, randomizer)
	sigmaDen = sigmaDen.AddPoints(sigmaDen, kappaTimesLambdaJ)
	if k, ok := t.sigmaNumerator.(*poly2.PedersenCommitmentOpening); ok {
		if sigmaNum.Equal(curve.Point.Pedersen(k[0], k[1])) != 1 {
			return errors.New("invalid commitment")
		}
	}
	if k, ok := t.sigmaDenominator.(*poly2.PedersenCommitmentOpening); ok {
		if sigmaNum.Equal(curve.Point.Pedersen(k[0], k[1])) != 1 {
			return errors.New("invalid commitment")
		}
	}
	return nil
}
