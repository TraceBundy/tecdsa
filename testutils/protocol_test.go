package testutils

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/key"
	"github.com/PlatONnetwork/tecdsa/sign"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/btree"
	"testing"
)

func TestShouldReshareTranscriptsCorrectly(t *testing.T) {
	setup := NewProtocolSetup(curve.K256, 4, 2, RandomSeed())
	noCorruption := 0
	corruptedDealings := 1
	random, err := Round.Random(setup, 4, corruptedDealings)
	assert.Nil(t, err)
	_, err = Round.ReshareOfMasked(setup, random, 1, noCorruption)
	assert.NotNil(t, err)

	reshared2, err := Round.ReshareOfMasked(setup, random, 2, corruptedDealings)
	assert.Nil(t, err)
	reshared3, err := Round.ReshareOfMasked(setup, random, 3, corruptedDealings)
	assert.Nil(t, err)
	reshared4, err := Round.ReshareOfMasked(setup, random, 4, corruptedDealings)
	assert.Nil(t, err)
	assert.Equal(t, 1, reshared2.ConstantTerm().Equal(reshared3.ConstantTerm()))
	assert.Equal(t, 1, reshared2.ConstantTerm().Equal(reshared4.ConstantTerm()))

	_, err = Round.ReshareOfUnmasked(setup, reshared2, 1, noCorruption)
	assert.NotNil(t, err)
	unmasked, err := Round.ReshareOfUnmasked(setup, reshared2, 2, corruptedDealings)
	assert.Equal(t, 1, reshared2.ConstantTerm().Equal(unmasked.ConstantTerm()))

	_, err = Round.Multiply(setup, random, unmasked, 1, noCorruption)
	assert.NotNil(t, err)
	_, err = Round.Multiply(setup, random, unmasked, 2, noCorruption)
	assert.NotNil(t, err)
	_, err = Round.Multiply(setup, random, unmasked, 3, corruptedDealings)
	assert.Nil(t, err)

}

func TestShouldMultiplyTranscriptsCorrectly(t *testing.T) {
	setup := NewProtocolSetup(curve.K256, 4, 2, RandomSeed())
	dealers := 4
	corruptedDealings := 1
	randoma, err := Round.Random(setup, dealers, corruptedDealings)
	assert.Nil(t, err)
	randomb, err := Round.Random(setup, dealers, corruptedDealings)
	assert.Nil(t, err)
	randomc, err := Round.ReshareOfMasked(setup, randoma, dealers, corruptedDealings)
	assert.Nil(t, err)
	randomd, err := Round.ReshareOfMasked(setup, randomb, dealers, corruptedDealings)
	assert.Nil(t, err)

	productad, err := Round.Multiply(setup, randoma, randomd, dealers, corruptedDealings)
	assert.Nil(t, err)
	productbc, err := Round.Multiply(setup, randomb, randomc, dealers, corruptedDealings)
	assert.Nil(t, err)

	resharead, err := Round.ReshareOfMasked(setup, productad, dealers, corruptedDealings)
	assert.Nil(t, err)
	resharebc, err := Round.ReshareOfMasked(setup, productbc, dealers, corruptedDealings)
	assert.Nil(t, err)
	assert.Equal(t, 1, resharead.ConstantTerm().Equal(resharebc.ConstantTerm()))
}

func TestShouldReshareTranscriptsWithDynamicThreshold(t *testing.T) {
	setup := NewProtocolSetup(curve.K256, 5, 2, RandomSeed())
	noCorruption := 0
	corruptedDealings := 1
	randoma, err := Round.Random(setup, 5, corruptedDealings)
	assert.Nil(t, err)
	_, err = Round.ReshareOfMasked(setup, randoma, 1, noCorruption)
	assert.NotNil(t, err)

	resharedb, err := Round.ReshareOfMasked(setup, randoma, 2, corruptedDealings)
	assert.Nil(t, err)

	setup.ModifyThreshold(1)
	setup.RemoveNodes(2)
	_, err = Round.ReshareOfUnmasked(setup, resharedb, 1, noCorruption)
	assert.NotNil(t, err)
	resharedc, err := Round.ReshareOfUnmasked(setup, resharedb, 2, corruptedDealings)
	resharedd, err := Round.ReshareOfUnmasked(setup, resharedb, 3, corruptedDealings)
	assert.Equal(t, 1, resharedc.ConstantTerm().Equal(resharedd.ConstantTerm()))
}
func TestShouldMultiplyTranscriptsWithDynamicThreshold(t *testing.T) {
	setup := NewProtocolSetup(curve.K256, 5, 2, RandomSeed())
	corruptedDealings := 1
	randoma, err := Round.Random(setup, 5, corruptedDealings)
	assert.Nil(t, err)
	randomb, err := Round.Random(setup, 5, corruptedDealings)
	assert.Nil(t, err)
	resharedc, err := Round.ReshareOfMasked(setup, randoma, 3, corruptedDealings)
	assert.Nil(t, err)

	setup.ModifyThreshold(1)
	setup.RemoveNodes(2)

	_, err = Round.Multiply(setup, randomb, resharedc, 1, 0)
	assert.NotNil(t, err)
	_, err = Round.Multiply(setup, randomb, resharedc, 2, 0)
	assert.NotNil(t, err)
	_, err = Round.Multiply(setup, randomb, resharedc, 3, corruptedDealings)
	assert.Nil(t, err)
}
func RandomSubset(shares *btree.Map[common.NodeIndex, *sign.ThresholdEcdsaSigShareInternal], include int) *btree.Map[common.NodeIndex, *sign.ThresholdEcdsaSigShareInternal] {
	rng := RandomSeed().Rng()
	var result btree.Map[common.NodeIndex, *sign.ThresholdEcdsaSigShareInternal]
	keys := shares.Keys()
	for result.Len() != include {
		key := keys[int(rng.Uint32())%len(keys)]
		if _, ok := result.Get(key); !ok {
			value, _ := shares.Get(key)
			result.Set(key, value)
		}
	}
	return &result
}

func TestShouldBasicSigningProtocolWork(t *testing.T) {
	testSigSerialization := func(sig *sign.ThresholdEcdsaCombinedSigInternal) error {
		return nil
	}
	nodes := 4
	threshold := nodes / 3
	numberOfDealingsCorrupted := threshold
	setup, err := NewSignatureProtocolSetup(curve.K256, nodes, threshold, numberOfDealingsCorrupted, RandomSeed())
	assert.Nil(t, err)
	rng := RandomSeed().Rng()

	var signedMessage [32]byte
	rng.FillUint8(signedMessage[:])
	var randomBeacon [32]byte
	rng.FillUint8(signedMessage[:])
	derivationPath := key.NewBip32([]uint32{1, 2, 3})
	proto := NewSignatureProtocolExecution(setup, signedMessage[:], randomBeacon[:], derivationPath)
	shares, err := proto.GenerateShares()
	assert.Nil(t, err)
	for i := 4; i <= nodes; i++ {
		shares := RandomSubset(shares, i)
		if shares.Len() < threshold {
			_, err := proto.GenerateSignature(shares)
			assert.NotNil(t, err)
		} else {
			sig, err := proto.GenerateSignature(shares)
			assert.Nil(t, err)
			testSigSerialization(sig)
			assert.Nil(t, proto.VerifySignature(sig))
		}
	}
}
