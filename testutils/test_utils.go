package testutils

import (
	"github.com/TraceBundy/tecdsa/common"
	"github.com/TraceBundy/tecdsa/curve"
	"github.com/TraceBundy/tecdsa/dealings"
	"github.com/TraceBundy/tecdsa/mega"
	"github.com/TraceBundy/tecdsa/rand"
	seed2 "github.com/TraceBundy/tecdsa/seed"
)

func CorruptDealing(dealing *dealings.IDkgDealingInternal, corruptionTargets []common.NodeIndex, seed *seed2.Seed) (*dealings.IDkgDealingInternal, error) {
	curveType := dealing.Commitment.CurveType()
	rng := seed.Rng()
	randomizer := curve.Scalar.Random(curveType, rng)
	var ciphertext mega.MEGaCiphertext
	switch c := dealing.Ciphertext.(type) {
	case *mega.MEGaCiphertextSingle:
		ctexts := make([]curve.EccScalar, len(c.CTexts), len(c.CTexts))
		for i, c := range c.CTexts {
			ctexts[i] = c.Clone()
		}
		for _, target := range corruptionTargets {
			ctexts[target] = ctexts[target].Add(ctexts[target], randomizer)
		}
		ciphertext = &mega.MEGaCiphertextSingle{
			EphemeralKey: c.EphemeralKey.Clone(),
			PopPublicKey: c.PopPublicKey.Clone(),
			PopProof:     c.PopProof,
			CTexts:       ctexts,
		}
	case *mega.MEGaCiphertextPair:
		ctexts := make([][2]curve.EccScalar, len(c.CTexts), len(c.CTexts))
		for i, c := range c.CTexts {
			ctexts[i][0] = c[0]
			ctexts[i][1] = c[1]
		}
		for _, target := range corruptionTargets {
			ctexts[target][0] = ctexts[target][0].Add(ctexts[target][0], randomizer)
		}
		ciphertext = &mega.MEGaCiphertextPair{
			EphemeralKey: c.EphemeralKey.Clone(),
			PopPublicKey: c.PopPublicKey.Clone(),
			PopProof:     c.PopProof,
			CTexts:       ctexts,
		}
	}
	var proof dealings.ZkProof
	if dealing.Proof != nil {
		proof = dealing.Proof.Clone()
	}
	return &dealings.IDkgDealingInternal{
		Ciphertext: ciphertext,
		Commitment: dealing.Commitment.Clone(),
		Proof:      proof,
	}, nil
}

func CorruptDealingForAllRecipients(dealing *dealings.IDkgDealingInternal, seed *seed2.Seed) (*dealings.IDkgDealingInternal, error) {
	var all []common.NodeIndex
	for i := 0; i < dealing.Ciphertext.Recipients(); i++ {
		all = append(all, common.NodeIndex(i))
	}
	return CorruptDealing(dealing, all, seed)

}

func TestPublicDealingVerification(setup *ProtocolSetup, dealing *dealings.IDkgDealingInternal, transcriptType dealings.IDkgTranscriptOperationInternal, dealerIndex common.NodeIndex) {
	if err := dealing.PubliclyVerify(curve.K256, transcriptType, setup.Threshold, dealerIndex, setup.Receivers, setup.Ad); err != nil {
		panic("created a publicly invalid dealing")
	}
	if dealing.PubliclyVerify(curve.K256, transcriptType, setup.Threshold, dealerIndex+1, setup.Receivers, setup.Ad) == nil {
		panic("created a publicly invalid dealing")
	}
	if dealing.PubliclyVerify(curve.K256, transcriptType, setup.Threshold, dealerIndex+1, setup.Receivers+1, setup.Ad) == nil {
		panic("created a publicly invalid dealing")
	}
	if dealing.PubliclyVerify(curve.K256, transcriptType, setup.Threshold, dealerIndex+1, setup.Receivers+1, []byte("wrong ad")) == nil {
		panic("created a publicly invalid dealing")
	}
}

func RandomSeed() *seed2.Seed {
	//key, _ := crand.Prime(crand.Reader, 256)
	var key [32]byte
	rng := rand.NewChaCha20(key[:])
	return seed2.FromRng(rng)
}
