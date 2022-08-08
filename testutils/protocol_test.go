package testutils

import (
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/stretchr/testify/assert"
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
