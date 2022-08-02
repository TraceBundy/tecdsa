package testutils

import (
	"fmt"
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/mega"
	seed2 "github.com/PlatONnetwork/tecdsa/seed"
)

type ProtocolSetup struct {
	Threshold     int
	Receivers     int
	Ad            []byte
	Pk            []*mega.MEGaPublicKey
	Sk            []*mega.MEGaPrivateKey
	Seed          *seed2.Seed
	ProtocolRound int
}

func NewProtocolSetup(curveType curve.EccCurveType, receivers int, threshold int, seed *seed2.Seed) *ProtocolSetup {
	rng := seed.Rng()
	var ad [32]byte
	rng.FillUint8(ad[:])
	pk := make([]*mega.MEGaPublicKey, receivers, receivers)
	sk := make([]*mega.MEGaPrivateKey, receivers, receivers)
	for i := 0; i < receivers; i++ {
		k := mega.PrivateKey.GeneratePrivateKey(curveType, rng)
		pk[i] = k.PublicKey()
		sk[i] = k
	}

	return &ProtocolSetup{
		Threshold:     threshold,
		Receivers:     receivers,
		Ad:            ad[:],
		Pk:            pk,
		Sk:            sk,
		Seed:          seed,
		ProtocolRound: 0,
	}
}

func (p *ProtocolSetup) NextDealingSeed() *seed2.Seed {
	seed := p.Seed.Derive(fmt.Sprintf("ic-crypto-tecdsa-round-%d", p.ProtocolRound))
	p.ProtocolRound += 1
	return seed
}
func (p *ProtocolSetup) RemoveNodes(removing int) {
	p.Receivers -= removing
	p.Pk = p.Pk[0:p.Receivers]
	p.Sk = p.Sk[0:p.Receivers]
}
func (p *ProtocolSetup) ModifyThreshold(threshold int) {
	p.Threshold = threshold
}
func (p *ProtocolSetup) ReceiverInfo() ([]*mega.MEGaPrivateKey, []*mega.MEGaPublicKey, []common.NodeIndex) {
	info := make([]common.NodeIndex, p.Receivers, p.Receivers)
	pk := make([]*mega.MEGaPublicKey, p.Receivers, p.Receivers)
	sk := make([]*mega.MEGaPrivateKey, p.Receivers, p.Receivers)

	for i := 0; i < p.Receivers; i++ {
		sk[i] = p.Sk[i]
		pk[i] = p.Pk[i]
		info[i] = common.NodeIndex(i)
	}
	return sk, pk, info
}
