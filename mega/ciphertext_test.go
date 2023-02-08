package mega

import (
	"encoding/hex"
	"github.com/TraceBundy/tecdsa/common"
	"github.com/TraceBundy/tecdsa/curve"
	seed2 "github.com/TraceBundy/tecdsa/seed"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMegaSingleSmokeTest(t *testing.T) {
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
	pa, err := ctext.Decrypt(ad, dealerIndex, 0, ask, apk)
	assert.Nil(t, err)
	assert.Equal(t, hex.EncodeToString(ptexta.Serialize()), hex.EncodeToString(pa.Serialize()))
	pb, err := ctext.Decrypt(ad, dealerIndex, 1, bsk, bpk)
	assert.Nil(t, err)
	assert.Equal(t, hex.EncodeToString(ptextb.Serialize()), hex.EncodeToString(pb.Serialize()))
}

func TestMegaPairSmokeTest(t *testing.T) {
	rng := seed2.FromBytes(genkey(43, 32)).Rng()
	ask := PrivateKey.GeneratePrivateKey(curve.K256, rng)
	bsk := PrivateKey.GeneratePrivateKey(curve.K256, rng)

	apk := ask.PublicKey()
	bpk := bsk.PublicKey()

	ad := []byte("assoc_data_test")
	ptexta := [2]curve.EccScalar{curve.Scalar.Random(curve.K256, rng), curve.Scalar.Random(curve.K256, rng)}
	ptextb := [2]curve.EccScalar{curve.Scalar.Random(curve.K256, rng), curve.Scalar.Random(curve.K256, rng)}
	dealerIndex := common.NodeIndex(0)
	seed := seed2.FromRng(rng)
	ctext, err := EncryptCiphertextPair(seed, [][2]curve.EccScalar{ptexta, ptextb}, []*MEGaPublicKey{apk, bpk}, dealerIndex, ad)
	assert.Nil(t, err)
	pa, err := ctext.Decrypt(ad, dealerIndex, 0, ask, apk)
	assert.Nil(t, err)
	for i, p := range pa {
		assert.Equal(t, hex.EncodeToString(ptexta[i].Serialize()), hex.EncodeToString(p.Serialize()))
	}
	pb, err := ctext.Decrypt(ad, dealerIndex, 1, bsk, bpk)
	assert.Nil(t, err)
	for i, p := range pb {
		assert.Equal(t, hex.EncodeToString(ptextb[i].Serialize()), hex.EncodeToString(p.Serialize()))
	}
}
