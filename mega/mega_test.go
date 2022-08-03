package mega

import (
	"github.com/PlatONnetwork/tecdsa/common"
	curve "github.com/PlatONnetwork/tecdsa/curve"
	seed2 "github.com/PlatONnetwork/tecdsa/seed"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMegaShouldRejectInvalidPop(t *testing.T) {
	curveType := curve.K256
	rng := seed2.FromBytes(genkey(42, 32)).Rng()
	ask := PrivateKey.GeneratePrivateKey(curve.K256, rng)
	bsk := PrivateKey.GeneratePrivateKey(curve.K256, rng)

	apk := ask.PublicKey()
	bpk := bsk.PublicKey()

	ad := []byte("assoc_data_test")
	ptexta := curve.Scalar.Random(curve.K256, rng)
	ptextb := curve.Scalar.Random(curve.K256, rng)
	dealerIndex := common.NodeIndex(0)
	seed := seed2.FromRng(rng)
	ctext, err := EncryptCiphertextSingle(seed, []curve.EccScalar{ptexta, ptextb}, []*MEGaPublicKey{apk, bpk}, dealerIndex, ad)
	assert.Nil(t, err)
	_, err = ctext.Decrypt(ad, dealerIndex, 1, bsk, bpk)
	assert.Nil(t, err)
	_, err = ctext.Decrypt([]byte("wrong_ad"), dealerIndex, 1, bsk, bpk)
	assert.NotNil(t, err)

	badPop := ctext.Clone()
	badPop.PopPublicKey = ctext.EphemeralKey
	_, err = badPop.Decrypt(ad, dealerIndex, 1, bsk, bpk)
	assert.NotNil(t, err)
	badEph := ctext.Clone()
	badEph.EphemeralKey, _ = curve.Point.HashToPoint(curveType, []byte("input"), []byte("dst"))
	_, err = badEph.Decrypt(ad, dealerIndex, 1, bsk, bpk)
	assert.NotNil(t, err)
}
