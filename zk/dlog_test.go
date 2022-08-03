package zk

import (
	"github.com/PlatONnetwork/tecdsa/curve"
	seed2 "github.com/PlatONnetwork/tecdsa/seed"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestZkDlogEqProofWork(t *testing.T) {
	curveType := curve.K256
	rng := rng()
	var ad [32]byte
	rng.FillUint8(ad[:])
	seed := seed2.FromRng(rng)
	var ig [32]byte
	rng.FillUint8(ig[:])
	var ih [32]byte
	rng.FillUint8(ih[:])
	g, err := curve.Point.HashToPoint(curveType, ig[:], []byte("g_domain"))
	assert.Nil(t, err)
	h, err := curve.Point.HashToPoint(curveType, ih[:], []byte("h_domain"))
	assert.Nil(t, err)
	x := curve.Scalar.Random(curveType, rng)
	gx := g.Clone().ScalarMul(g, x)
	hx := h.Clone().ScalarMul(h, x)
	proof, err := ProofOfDLogEquivalenceIns.Create(seed, x, g, h, ad[:])
	assert.Nil(t, err)
	assert.Nil(t, proof.Verify(g, h, gx, hx, ad[:]))
	assert.NotNil(t, proof.Verify(h, g, gx, hx, ad[:]))
	assert.NotNil(t, proof.Verify(g, h, hx, gx, ad[:]))
}
