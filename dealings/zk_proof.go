package dealings

import "github.com/PlatONnetwork/tecdsa/zk"

const (
	ProofOfMaskedResharing = ZkProofType(0)
	ProofOfProduct         = ZkProofType(1)
)

type ZkProofType int

type ZkProof interface {
	Type() ZkProofType
}

type MaskedResharingProof struct {
	*zk.ProofOfEqualOpenings
}

func (MaskedResharingProof) Type() ZkProofType {
	return ProofOfMaskedResharing
}

type ProductProof struct {
	*zk.ProofOfProduct
}

func (ProductProof) Type() ZkProofType {
	return ProofOfMaskedResharing
}
