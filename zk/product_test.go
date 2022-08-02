package zk

import (
	"github.com/PlatONnetwork/tecdsa/curve"
	seed2 "github.com/PlatONnetwork/tecdsa/seed"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestZkMulProofWork(t *testing.T) {
	curveType := curve.K256
	rng := rng()
	var ad [32]byte
	rng.FillUint8(ad[:])
	seed := seed2.FromRng(rng)
	lhs := curve.Scalar.Random(curveType, rng)
	rhs := curve.Scalar.Random(curveType, rng)
	masking := curve.Scalar.Random(curveType, rng)
	product := lhs.Clone().Mul(lhs, rhs)
	productMasking := curve.Scalar.Random(curveType, rng)
	productC := curve.Point.Pedersen(product, productMasking)
	lhsC := curve.Point.MulByG(lhs)
	rhsC := curve.Point.Pedersen(rhs, masking)
	proof, err := ProofOfProductIns.Create(seed, lhs, rhs, masking, product, productMasking, ad[:])
	assert.Nil(t, err)
	assert.Nil(t, proof.Verify(lhsC, rhsC, productC, ad[:]))
	assert.NotNil(t, proof.Verify(rhsC, lhsC, productC, ad[:]))
	assert.NotNil(t, proof.Verify(lhsC, rhsC, lhsC, ad[:]))
}
func TestZkMulProofRejected(t *testing.T) {
	curveType := curve.K256
	rng := rng()
	var ad [32]byte
	rng.FillUint8(ad[:])
	seed := seed2.FromRng(rng)
	lhs := curve.Scalar.Random(curveType, rng)
	rhs := curve.Scalar.Random(curveType, rng)
	masking := curve.Scalar.Random(curveType, rng)
	product := curve.Scalar.Random(curveType, rng)
	productMasking := curve.Scalar.Random(curveType, rng)
	productC := curve.Point.Pedersen(product, productMasking)
	lhsC := curve.Point.MulByG(lhs)
	rhsC := curve.Point.Pedersen(rhs, masking)
	proof, err := ProofOfProductIns.Create(seed, lhs, rhs, masking, product, productMasking, ad[:])
	assert.Nil(t, err)
	assert.NotNil(t, proof.Verify(lhsC, rhsC, productC, ad[:]))
}
