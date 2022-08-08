package testutils

import (
	"crypto/sha256"
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/key"
	seed2 "github.com/PlatONnetwork/tecdsa/seed"
	"github.com/PlatONnetwork/tecdsa/sign"
	"github.com/tidwall/btree"
)

type SignatureProtocolSetup struct {
	Setup            *ProtocolSetup
	Key              *ProtocolRound
	Kappa            *ProtocolRound
	Lambda           *ProtocolRound
	KeyTimesLambda   *ProtocolRound
	KappaTimesLambda *ProtocolRound
}

func NewSignatureProtocolSetup(curveType curve.EccCurveType, numberOfDealers int, threshold int, numberOfDealingsCorrupted int, seed *seed2.Seed) (*SignatureProtocolSetup, error) {
	setup := NewProtocolSetup(curveType, numberOfDealers, threshold, seed)
	key, err := Round.Random(setup, numberOfDealers, numberOfDealingsCorrupted)
	kappa, err := Round.Random(setup, numberOfDealers, numberOfDealingsCorrupted)
	lambda, err := Round.Random(setup, numberOfDealers, numberOfDealingsCorrupted)
	key, err = Round.ReshareOfMasked(setup, key, numberOfDealers, numberOfDealingsCorrupted)
	kappa, err = Round.ReshareOfMasked(setup, kappa, numberOfDealers, numberOfDealingsCorrupted)
	keyTimesLambda, err := Round.Multiply(setup, lambda, key, numberOfDealers, numberOfDealingsCorrupted)
	kappaTimesLambda, err := Round.Multiply(setup, lambda, kappa, numberOfDealers, numberOfDealingsCorrupted)
	return &SignatureProtocolSetup{
		Setup:            setup,
		Key:              key,
		Kappa:            kappa,
		Lambda:           lambda,
		KeyTimesLambda:   keyTimesLambda,
		KappaTimesLambda: kappaTimesLambda,
	}, nil
}

func (s SignatureProtocolSetup) PublicKey(path *key.DerivationPath) (*key.EcdsaPublicKey, error) {
	return sign.DerivePublicKey(&key.MasterEcdsaPublicKey{PublicKey: s.Key.Transcript.ConstantTerm().Serialize()}, path)
}

type SignatureProtocolExecution struct {
	Setup          *SignatureProtocolSetup
	SignedMessage  []byte
	HashedMessage  []byte
	RandomBeacon   []byte
	DerivationPath *key.DerivationPath
}

func NewSignatureProtocolExecution(setup *SignatureProtocolSetup, signedMessage []byte, randomBeacon []byte, derivationPath *key.DerivationPath) *SignatureProtocolExecution {
	hashedMessage := sha256.New().Sum(signedMessage)
	return &SignatureProtocolExecution{
		Setup:          setup,
		SignedMessage:  signedMessage,
		HashedMessage:  hashedMessage,
		RandomBeacon:   randomBeacon,
		DerivationPath: derivationPath,
	}
}
func (s SignatureProtocolExecution) GenerateShares() (*btree.Map[common.NodeIndex, *sign.ThresholdEcdsaSigShareInternal], error) {
	var shares btree.Map[common.NodeIndex, *sign.ThresholdEcdsaSigShareInternal]
	for nodeIndex := 0; nodeIndex < s.Setup.Setup.Receivers; nodeIndex++ {
		share, err := sign.NewThresholdEcdsaSigShareInternal(s.DerivationPath, s.HashedMessage, s.RandomBeacon, s.Setup.Key.Transcript, s.Setup.Kappa.Transcript, s.Setup.Lambda.Openings[nodeIndex], s.Setup.KappaTimesLambda.Openings[nodeIndex], s.Setup.KeyTimesLambda.Openings[nodeIndex], curve.K256)
		if err != nil {
			return nil, err
		}
		if err := share.Verify(s.DerivationPath, s.HashedMessage, s.RandomBeacon, common.NodeIndex(nodeIndex), s.Setup.Key.Transcript, s.Setup.Kappa.Transcript, s.Setup.Lambda.Transcript, s.Setup.KappaTimesLambda.Transcript, s.Setup.KeyTimesLambda.Transcript, curve.K256); err != nil {
			return nil, err
		}
		shares.Set(common.NodeIndex(nodeIndex), share)
	}
	return &shares, nil
}
func (s SignatureProtocolExecution) GenerateSignature(shares *btree.Map[common.NodeIndex, *sign.ThresholdEcdsaSigShareInternal]) (*sign.ThresholdEcdsaCombinedSigInternal, error) {
	return sign.NewThresholdEcdsaCombinedSigInternal(s.DerivationPath, s.HashedMessage, s.RandomBeacon, s.Setup.Key.Transcript, s.Setup.Kappa.Transcript, s.Setup.Setup.Threshold, shares, curve.K256)
}

func (s SignatureProtocolExecution) VerifySignature(sig *sign.ThresholdEcdsaCombinedSigInternal) error {
	if err := sig.Verify(s.DerivationPath, s.HashedMessage, s.RandomBeacon, s.Setup.Kappa.Transcript, s.Setup.Key.Transcript, curve.K256); err != nil {
		return err
	}
	//pk, err := s.Setup.PublicKey(s.DerivationPath)
	//if err != nil {
	//	return err
	//}
	return nil
}
