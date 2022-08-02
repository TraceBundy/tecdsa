package dealings

import (
	crand "crypto/rand"
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/mega"
	poly2 "github.com/PlatONnetwork/tecdsa/poly"
	"github.com/PlatONnetwork/tecdsa/rand"
	seed2 "github.com/PlatONnetwork/tecdsa/seed"
	"github.com/stretchr/testify/assert"
	"testing"
)

func genRng() rand.Rand {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	return rng
}
func genPrivateKeys(curveType curve.EccCurveType, cnt int) ([]*mega.MEGaPrivateKey, []*mega.MEGaPublicKey) {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	privateKeys := make([]*mega.MEGaPrivateKey, 0, cnt)
	publicKeys := make([]*mega.MEGaPublicKey, 0, cnt)
	for i := 0; i < cnt; i++ {
		sk := mega.PrivateKey.GeneratePrivateKey(curveType, rng)
		privateKeys = append(privateKeys, sk)
		publicKeys = append(publicKeys, sk.PublicKey())
	}
	return privateKeys, publicKeys
}

func TestCreateRandomDealing(t *testing.T) {
	curveType := curve.K256

	rng := genRng()
	ad := []byte{1, 2, 3}
	privateKeys, publicKeys := genPrivateKeys(curveType, 5)
	threshold := 2
	dealerIndex := common.NodeIndex(0)
	shares := &RandomSecret{}
	dealing, err := NewIDkgDealingInternal(shares, curveType, seed2.FromRng(rng), threshold, publicKeys, dealerIndex, ad)
	assert.Nil(t, err)
	assert.Equal(t, threshold, dealing.Commitment.(*poly2.PedersenCommitment).Len())
	assert.Equal(t, len(privateKeys), len(dealing.Ciphertext.(*mega.MEGaCiphertextPair).CTexts))
	assert.Nil(t, dealing.Proof)
}

func TestCreateReshareUnmaskedDealing(t *testing.T) {
	curveType := curve.K256

	rng := genRng()
	ad := []byte{1, 2, 3}
	privateKeys, publicKeys := genPrivateKeys(curveType, 5)
	threshold := 2
	dealerIndex := common.NodeIndex(0)

	secret := curve.Scalar.Random(curveType, rng)
	shares := &ReshareOfUnmaskedSecret{secret}
	dealing, err := NewIDkgDealingInternal(shares, curveType, seed2.FromRng(rng), threshold, publicKeys, dealerIndex, ad)
	assert.Nil(t, err)
	assert.Equal(t, threshold, dealing.Commitment.(*poly2.SimpleCommitment).Len())
	assert.Equal(t, len(privateKeys), len(dealing.Ciphertext.(*mega.MEGaCiphertextSingle).CTexts))
}

func TestCreateReshareMaskedDealings(t *testing.T) {
	curveType := curve.K256

	rng := genRng()
	ad := []byte{1, 2, 3}
	privateKeys, publicKeys := genPrivateKeys(curveType, 5)
	threshold := 2
	dealerIndex := common.NodeIndex(0)

	secret := curve.Scalar.Random(curveType, rng)
	mask := curve.Scalar.Random(curveType, rng)
	shares := &ReshareOfMaskedSecret{S1: secret, S2: mask}
	dealing, err := NewIDkgDealingInternal(shares, curveType, seed2.FromRng(rng), threshold, publicKeys, dealerIndex, ad)
	assert.Nil(t, err)
	assert.Equal(t, threshold, dealing.Commitment.(*poly2.SimpleCommitment).Len())
	assert.Equal(t, len(privateKeys), len(dealing.Ciphertext.(*mega.MEGaCiphertextSingle).CTexts))
}

func TestCreateMultiDealing(t *testing.T) {
	curveType := curve.K256

	rng := genRng()
	ad := []byte{1, 2, 3}
	privateKeys, publicKeys := genPrivateKeys(curveType, 5)
	threshold := 2
	dealerIndex := common.NodeIndex(0)

	lhs := curve.Scalar.Random(curveType, rng)
	rhs := curve.Scalar.Random(curveType, rng)
	mask := curve.Scalar.Random(curveType, rng)
	shares := &UnmaskedTimesMaskedSecret{lhs, [2]curve.EccScalar{rhs, mask}}
	dealing, err := NewIDkgDealingInternal(shares, curveType, seed2.FromRng(rng), threshold, publicKeys, dealerIndex, ad)

	assert.Nil(t, err)
	assert.Equal(t, threshold, dealing.Commitment.(*poly2.PedersenCommitment).Len())
	assert.Equal(t, len(privateKeys), len(dealing.Ciphertext.(*mega.MEGaCiphertextPair).CTexts))
}

func TestInvalidCreateDealingRequests(t *testing.T) {
	curveType := curve.K256

	rng := genRng()
	ad := []byte{1, 2, 3}
	_, publicKeys := genPrivateKeys(curveType, 5)
	dealerIndex := common.NodeIndex(0)

	shares := &RandomSecret{}
	_, err := NewIDkgDealingInternal(shares, curveType, seed2.FromRng(rng), len(publicKeys)+1, publicKeys, dealerIndex, ad)
	assert.NotNil(t, err)
}
