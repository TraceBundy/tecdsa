package seed

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func testSeedOutput(t *testing.T, seed *Seed, expected string) {
	var output [32]byte
	rng := seed.Rng()
	rng.FillUint8(output[:])
	assert.Equal(t, expected, hex.EncodeToString(output[:]))
}

func TestSeedOutput(t *testing.T) {
	var value [32]byte
	for i, _ := range value {
		value[i] = 42
	}
	testSeedOutput(t, FromBytes(value[:]), "21b03e2c906a3c20d8159b65a459991238fd3bfb8a36c0af904cd1b12a109853")
	testSeedOutput(t, FromBytes(value[:]).Derive("label1"), "6f3377835641b9ea865e077ae3d09806fa7cd77af4ad7a6674400d8e0683517a")
	testSeedOutput(t, FromBytes(value[:]).Derive("label1").Derive("label2"), "545e10f21a984c7f33a03ffb1be596ae967f7b397fd086d76ccf71b3f2a43ef3")
	rng := FromBytes(value[:]).Rng()
	testSeedOutput(t, FromRng(rng), "2e7af894bb91c48e2b72be9627dbc960d7800ef7569c8f6f0f3d9873c7337c9a")
	testSeedOutput(t, FromRng(rng), "2bb9a6469fff531083abd8f85c3d7ffa78090f725546a9633a35c0c4582c9b5c")
}
