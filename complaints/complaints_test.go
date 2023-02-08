package complaints

import (
	crand "crypto/rand"
	"github.com/TraceBundy/tecdsa/common"
	"github.com/TraceBundy/tecdsa/curve"
	"github.com/TraceBundy/tecdsa/dealings"
	"github.com/TraceBundy/tecdsa/mega"
	"github.com/TraceBundy/tecdsa/rand"
	seed2 "github.com/TraceBundy/tecdsa/seed"
	"github.com/stretchr/testify/assert"
	"testing"
)

func genRng() rand.Rand {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	return rng
}

func TestShouldComplaintSystemWork(t *testing.T) {
	//curveType := curve.K256
}
func TestShouldComplaintVerificationRejectSpuriousComplaints(t *testing.T) {
	curveType := curve.K256
	rng := genRng()
	ad := []byte("assoc_data_test")
	sk := mega.PrivateKey.GeneratePrivateKey(curveType, rng)
	pk := sk.PublicKey()
	dealerIndex := common.NodeIndex(0)
	receiverIndex := common.NodeIndex(0)
	threshold := 1
	dealing, err := dealings.NewIDkgDealingInternal(&dealings.RandomSecret{}, curveType, seed2.FromRng(rng), threshold, []*mega.MEGaPublicKey{pk}, dealerIndex, ad)
	assert.Nil(t, err)

	complaint, err := NewComplaintInternal(seed2.FromRng(rng), dealing, dealerIndex, receiverIndex, sk, pk, ad)
	assert.Nil(t, err)
	assert.NotNil(t, complaint.Verify(dealing, dealerIndex, 0, pk, ad))

}
