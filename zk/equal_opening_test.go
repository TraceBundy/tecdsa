package zk

import (
	crand "crypto/rand"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/rand"
	seed2 "github.com/PlatONnetwork/tecdsa/seed"
	"github.com/stretchr/testify/assert"
	"testing"
)

func rng() *rand.ChaCha20 {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	return rng
}
func TestZkEqualOpeningsProofWork(t *testing.T)  {
	curveType := curve.K256
	rng := rng()
	var ad [32]byte
	rng.FillUint8(ad[:])
	seed := seed2.FromRng(rng)
	secret := curve.Scalar.Random(curveType, rng)
	masking := curve.Scalar.Random(curveType, rng)

	pedersen := curve.Point.Pedersen(secret, masking)
	simple := curve.Point.MulByG(secret)
	proof, err := ProofOfEqualOpeningsIns.Create(seed, secret, masking, ad[:])
	assert.Nil(t, err)
	assert.Nil(t, proof.Verify(pedersen, simple, ad[:]))
	assert.NotNil(t, proof.Verify(simple, simple, ad[:]))
	assert.NotNil(t,  proof.Verify(simple, pedersen, ad[:]))
	assert.NotNil(t,  proof.Verify(pedersen, pedersen, ad[:]))
}
