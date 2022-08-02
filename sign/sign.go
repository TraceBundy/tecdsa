package sign

import (
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/dealings"
	"github.com/PlatONnetwork/tecdsa/key"
	poly2 "github.com/PlatONnetwork/tecdsa/poly"
	ro2 "github.com/PlatONnetwork/tecdsa/ro"
	"github.com/pkg/errors"
)

func EcdsaConversion(pt curve.EccPoint) (curve.EccScalar, error) {
	x := pt.AffineX().AsBytes()
	return curve.Scalar.FromBytesWide(pt.CurveType(), x)
}

func ConvertHashToInteger(hashedMsg []byte, curveType curve.EccCurveType) (curve.EccScalar, error) {
	return curve.Scalar.FromBytesWide(curveType, hashedMsg)
}

func DeriveRho(curveType curve.EccCurveType, hashedMsg []byte, randomness []byte, derivationPath *key.DerivationPath, keyTranscript *dealings.IDkgTranscriptInternal, presigTranscript *dealings.IDkgTranscriptInternal) (curve.EccScalar, curve.EccScalar, curve.EccScalar, curve.EccPoint, error) {
	var preSig curve.EccPoint
	if p, ok := presigTranscript.CombinedCommitment.(*dealings.InterpolationCommitment); ok && p.PolynomialCommitment.Type() == poly2.Simple {
		preSig = p.PolynomialCommitment.(*poly2.SimpleCommitment).ConstantTerm()
	} else {
		return nil, nil, nil, nil, errors.New("unexpected commitment type")
	}
	keyTweak, _, err := derivationPath.DeriveTweak(keyTranscript.ConstantTerm())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ro := ro2.NewRandomOracle("ic-crypto-tecdsa-rerandomize-presig")
	ro.AddBytesString("randomness", randomness)
	ro.AddBytesString("hashed_message", hashedMsg)
	ro.AddPoint("pre_sig", preSig)
	ro.AddScalar("key_tweak", keyTweak)
	randomizer, err := ro.OutputScalar(curveType)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	randomizedPresig := preSig.Clone().AddPoints(preSig, curve.Point.GeneratorG(curveType).ScalarMul(curve.Point.GeneratorG(curveType), randomizer))
	rho, err := EcdsaConversion(randomizedPresig)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return rho, keyTweak, randomizer, randomizedPresig, nil
}

/// Returns a public key derived from `master_public_key` according to the
/// `derivation_path`.  The algorithm id of the derived key is the same
/// as the algorithm id of `master_public_key`.
func DerivePublicKey(master *key.MasterEcdsaPublicKey, derivationPath *key.DerivationPath) (*key.EcdsaPublicKey, error) {
	pk, err := curve.Point.Deserialize(curve.K256, master.PublicKey)
	if err != nil {
		return nil, err
	}
	keyTweak, chainKey, err := derivationPath.DeriveTweak(pk)
	if err != nil {
		return nil, err
	}
	tweakg := curve.Point.MulByG(keyTweak)
	publicKey := tweakg.AddPoints(tweakg, pk)
	return &key.EcdsaPublicKey{
		PublicKey: publicKey.Serialize(),
		ChainKey:  chainKey,
	}, nil
}
