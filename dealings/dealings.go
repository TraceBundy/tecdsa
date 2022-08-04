package dealings

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/mega"
	poly2 "github.com/PlatONnetwork/tecdsa/poly"
	"github.com/PlatONnetwork/tecdsa/seed"
	"github.com/PlatONnetwork/tecdsa/zk"
	"github.com/pkg/errors"
)

func EncryptAndCommitSinglePolynomial(poly *poly2.Polynomial, num int, recipients []*mega.MEGaPublicKey, dealerIndex common.NodeIndex, ad []byte, seed *seed.Seed) (mega.MEGaCiphertext, poly2.PolynomialCommitment, error) {
	curveType := poly.CurveType()
	plaintexts := make([]curve.EccScalar, len(recipients), len(recipients))

	for idx, _ := range recipients {
		scalar := curve.Scalar.FromNodeIndex(curveType, common.NodeIndex(idx))
		vs := poly.EvaluateAt(scalar)
		plaintexts[idx] = vs
	}

	ciphertext, err := mega.EncryptCiphertextSingle(seed, plaintexts, recipients, dealerIndex, ad)
	if err != nil {
		return nil, nil, err
	}
	commitment, err := poly2.SimpleCM.Create(poly, num)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, commitment, nil
}

func EncryptAndCommitPairPolynomial(values *poly2.Polynomial, mask *poly2.Polynomial, num int, recipients []*mega.MEGaPublicKey, dealerIndex common.NodeIndex, ad []byte, seed *seed.Seed) (mega.MEGaCiphertext, poly2.PolynomialCommitment, error) {
	curveType := values.CurveType()
	plaintexts := make([][2]curve.EccScalar, len(recipients), len(recipients))
	for idx, _ := range recipients {
		scalar := curve.Scalar.FromNodeIndex(curveType, common.NodeIndex(idx))
		vs := values.EvaluateAt(scalar)
		ms := mask.EvaluateAt(scalar)
		plaintexts[idx] = [2]curve.EccScalar{vs, ms}
	}
	ciphertext, err := mega.EncryptCiphertextPair(seed, plaintexts, recipients, dealerIndex, ad)
	if err != nil {
		return nil, nil, err
	}
	commitment, err := poly2.PedersenCM.Create(values, mask, num)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, commitment, nil
}

type IDkgDealingInternal struct {
	Ciphertext mega.MEGaCiphertext
	Commitment poly2.PolynomialCommitment
	Proof      ZkProof
}

func NewIDkgDealingInternal(shares SecretShares, curveType curve.EccCurveType, seed *seed.Seed, threshold int, recipients []*mega.MEGaPublicKey, dealerIndex common.NodeIndex, ad []byte) (*IDkgDealingInternal, error) {
	if threshold == 0 || threshold > len(recipients) {
		return nil, errors.New("invalid threshold")
	}

	numCoefficients := threshold
	polyRng := seed.Derive("ic-crypto-tecdsa-create-dealing-polynomials").Rng()
	megaSeed := seed.Derive("ic-crypto-tecdsa-create-dealing-mega-encrypt")
	var commitment poly2.PolynomialCommitment
	var ciphertext mega.MEGaCiphertext
	var proof ZkProof
	var err error
	switch s := shares.(type) {
	case *RandomSecret:
		values := poly2.Poly.Random(curveType, numCoefficients, polyRng)
		mask := poly2.Poly.Random(curveType, numCoefficients, polyRng)
		ciphertext, commitment, err = EncryptAndCommitPairPolynomial(values, mask, numCoefficients, recipients, dealerIndex, ad, megaSeed)
		if err != nil {
			return nil, err
		}
	case *ReshareOfUnmaskedSecret:
		values, err := poly2.Poly.RandomWithConstant(s.S1, numCoefficients, polyRng)
		if err != nil {
			return nil, err
		}
		ciphertext, commitment, err = EncryptAndCommitSinglePolynomial(values, numCoefficients, recipients, dealerIndex, ad, megaSeed)
		if err != nil {
			return nil, err
		}
	case *ReshareOfMaskedSecret:
		values, err := poly2.Poly.RandomWithConstant(s.S1, numCoefficients, polyRng)
		if err != nil {
			return nil, err
		}
		if ciphertext, commitment, err = EncryptAndCommitSinglePolynomial(values, numCoefficients, recipients, dealerIndex, ad, megaSeed)err != nil {
			return nil, err
		}
		if p, err := zk.ProofOfEqualOpeningsIns.Create(seed.Derive(zk.ProofOfEqualOpeningsDst), s.S1, s.S2, ad); err != nil {
			return nil, err
		} else {
			rp := MaskedResharingProof{p}
			proof = &rp
		}
	case *UnmaskedTimesMaskedSecret:
		product := s.Left.Clone().Mul(s.Left, s.Right[0])
		productMasking := curve.Scalar.Random(curveType, polyRng)
		values, err := poly2.Poly.RandomWithConstant(product, numCoefficients, polyRng)
		if err != nil {
			return nil, err
		}
		mask, err := poly2.Poly.RandomWithConstant(productMasking, numCoefficients, polyRng)
		if ciphertext, commitment, err = EncryptAndCommitPairPolynomial(values, mask, numCoefficients, recipients, dealerIndex, ad, megaSeed); err != nil {
			return nil, err
		}
		pf, err := zk.ProofOfProductIns.Create(seed.Derive(zk.ProofOfProductDst), s.Left, s.Right[0], s.Right[1], product, productMasking, ad)
		proof = &ProductProof{pf}
	}

	return &IDkgDealingInternal{ciphertext, commitment, proof}, nil

}
func (dealing IDkgDealingInternal) PubliclyVerify(curveType curve.EccCurveType, transcriptType IDkgTranscriptOperationInternal, reconstructionThreshold int, dealerIndex common.NodeIndex, numberOfReceivers int, ad []byte) error {
	if dealing.Commitment.Len() != reconstructionThreshold {
		return errors.New("invalid commitment")
	}
	if dealing.Commitment.CurveType() != curveType {
		return errors.New("curve mismatch")
	}
	if err := dealing.Ciphertext.CheckValidity(numberOfReceivers, ad, dealerIndex); err != nil {
		return err
	}
	transcriptType
}
