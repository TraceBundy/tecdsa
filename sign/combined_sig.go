package sign

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/dealings"
	"github.com/PlatONnetwork/tecdsa/key"
	poly2 "github.com/PlatONnetwork/tecdsa/poly"
	"github.com/pkg/errors"
	"github.com/tidwall/btree"
)

type ThresholdEcdsaCombinedSigInternal struct {
	R curve.EccScalar
	S curve.EccScalar
}

func NewThresholdEcdsaCombinedSigInternal(derivationPath *key.DerivationPath, hashedMsg []byte, randomness []byte, keyTranscript *dealings.IDkgTranscriptInternal, presigTranscript *dealings.IDkgTranscriptInternal, reconstructionThreshold int, sigShares *btree.Map[common.NodeIndex, *ThresholdEcdsaSigShareInternal], curveType curve.EccCurveType) (*ThresholdEcdsaCombinedSigInternal, error) {
	if sigShares.Len() < reconstructionThreshold {
		return nil, errors.New("insufficient dealings")
	}
	rho, _, _, _, err := DeriveRho(curveType, hashedMsg, randomness, derivationPath, keyTranscript, presigTranscript)
	if err != nil {
		return nil, err
	}
	xValues := make([]common.NodeIndex, 0, reconstructionThreshold)
	numeratorSamples := make([]curve.EccScalar, 0, reconstructionThreshold)
	denominatorSamples := make([]curve.EccScalar, 0, reconstructionThreshold)
	count := 0
	sigShares.Scan(func(index common.NodeIndex, sigShare *ThresholdEcdsaSigShareInternal) bool {
		if count >= reconstructionThreshold {
			return true
		}
		xValues = append(xValues, index)
		if p, ok := sigShare.sigmaNumerator.(poly2.PedersenCommitmentOpening); ok {
			numeratorSamples = append(numeratorSamples, p[0])
		}
		if p, ok := sigShare.sigmaDenominator.(poly2.PedersenCommitmentOpening); ok {
			denominatorSamples = append(denominatorSamples, p[0])
		}

		return true
	})
	var coefficients *poly2.LagrangeCoefficients
	var numerator curve.EccScalar
	var denominator curve.EccScalar
	if coefficients, err = poly2.Lagrange.AtZero(curveType, xValues); err != nil {
		return nil, err
	}
	if numerator, err = coefficients.InterpolateScalar(numeratorSamples); err != nil {
		return nil, err
	}
	if denominator, err = coefficients.InterpolateScalar(denominatorSamples); err != nil {
		return nil, err
	}
	sigma := numerator.Mul(numerator, denominator.Invert(denominator))
	normSigma := sigma
	if sigma.IsHigh() {
		normSigma = sigma.Negate(sigma)
	}

	return &ThresholdEcdsaCombinedSigInternal{
		R: rho,
		S: normSigma,
	}, nil
}

func (t ThresholdEcdsaCombinedSigInternal) Verify(derivationPath *key.DerivationPath, hashedMsg []byte, randomness []byte, keyTranscript *dealings.IDkgTranscriptInternal, presigTranscript *dealings.IDkgTranscriptInternal, curveType curve.EccCurveType) error {
	if t.R.IsZero() == 1 || t.S.IsZero() == 1 {
		return errors.New("invalid signature")
	}
	msg, err := ConvertHashToInteger(hashedMsg, curveType)
	if err != nil {
		return err
	}
	rho, keyTweak, _, preSig, err := DeriveRho(curveType, hashedMsg, randomness, derivationPath, keyTranscript, presigTranscript)
	if err != nil {
		return err
	}
	if t.R.Equal(rho) == 0 || t.S.IsHigh() {
		return errors.New("invalid signature")
	}

	masterPublickKey := keyTranscript.ConstantTerm()
	tweakg := curve.Point.MulByG(keyTweak)
	publicKey := tweakg.AddPoints(tweakg, masterPublickKey)
	sInv := t.S.Clone().Invert(t.S)
	u1 := msg.Clone().Mul(msg, sInv)
	u2 := t.R.Clone().Mul(t.R, sInv)
	rp := curve.Point.MulPoints(curve.Point.GeneratorG(curveType), u1, publicKey, u2)
	if rp.IsInfinity() {
		return errors.New("invalid signature")
	}
	if rp.AffineX().Equal(preSig.AffineX()) == 0 {
		return errors.New("invalid signature")
	}
	return nil
}
