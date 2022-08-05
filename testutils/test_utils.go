package testutils

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/dealings"
	"github.com/PlatONnetwork/tecdsa/mega"
	seed2 "github.com/PlatONnetwork/tecdsa/seed"
)

func CorruptDealing(dealing *dealings.IDkgDealingInternal, corruptionTargets []common.NodeIndex, seed seed2.Seed) (*dealings.IDkgDealingInternal, error) {
	curveType := dealing.Commitment.CurveType()
	rng := seed.Rng()
	randomizer := curve.Scalar.Random(curveType, rng)
	var ciphertext mega.MEGaCiphertext
	switch c := dealing.Ciphertext.(type) {
	case *mega.MEGaCiphertextSingle:
		ctexts := make([]curve.EccScalar, len(c.CTexts), len(c.CTexts))
		for i, c := range ctexts {
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
		for i, c := range ctexts {
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
	return &dealings.IDkgDealingInternal{
		Ciphertext: ciphertext,
		Commitment: dealing.Commitment.Clone(),
		Proof:      dealing.Proof.Clone(),
	}, nil
}

func CorruptDealingForAllRecipients(dealing *dealings.IDkgDealingInternal, seed seed2.Seed) (*dealings.IDkgDealingInternal, error) {
	var all []common.NodeIndex
	for i := 0; i < dealing.Ciphertext.Recipients(); i++ {
		all = append(all, common.NodeIndex(i))
	}
	return CorruptDealing(dealing, all, seed)

}
