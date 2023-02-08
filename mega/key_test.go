package mega

import (
	crand "crypto/rand"
	"encoding/hex"
	"github.com/TraceBundy/tecdsa/curve"
	"github.com/TraceBundy/tecdsa/rand"
	seed2 "github.com/TraceBundy/tecdsa/seed"
	"github.com/stretchr/testify/assert"
	"testing"
)

func genkey(d byte, size int) []byte {
	key := make([]byte, size)
	for i := range key {
		key[i] = d
	}
	return key[:]
}

func genRng() rand.Rand {
	key, _ := crand.Prime(crand.Reader, 256)
	rng := rand.NewChaCha20(key.Bytes())
	return rng
}
func all() []curve.EccCurveType {
	return []curve.EccCurveType{curve.K256}
}
func TestGenKeypair(t *testing.T) {
	key := genkey(0x42, 32)
	seed := seed2.FromBytes(key[:])
	pk, sk, err := GenKeypair(curve.K256, seed)
	assert.Nil(t, err)
	assert.Equal(t, "078af152fb1edc2488a6d414ac13e76de66904648c585dc5f5032b3c022716cd", hex.EncodeToString(sk.Serialize()))
	assert.Equal(t, "027e4c1145be85c1d62c24be6ff81f837a1c63d4051071233569b55fb410da4ebd", hex.EncodeToString(pk.Serialize()))
}

func TestMegaKeyValidity(t *testing.T) {
	rng := genRng()
	for _, curveType := range all() {
		sk := PrivateKey.GeneratePrivateKey(curveType, rng)
		pk := sk.PublicKey()
		pkBytes := pk.Serialize()
		assert.Nil(t, VerifyMegaPublicKey(curveType, pkBytes))
		pkBytes[0] ^= 1
		assert.Nil(t, VerifyMegaPublicKey(curveType, pkBytes))
		pkBytes[0] ^= 2
		assert.NotNil(t, VerifyMegaPublicKey(curveType, pkBytes))
		max := genkey(0xff, curveType.PointBytes())
		max[0] = 2
		assert.NotNil(t, VerifyMegaPublicKey(curveType, pkBytes))
	}
}
