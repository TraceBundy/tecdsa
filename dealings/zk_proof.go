package dealings

import "github.com/PlatONnetwork/tecdsa/zk"

const (
	ProofOfMaskedResharing = ZkProofType(0)
	ProofOfProduct         = ZkProofType(1)
)

type ZkProofType int

type ZkProof interface {
	Type() ZkProofType
	Clone() ZkProof
}

type MaskedResharingProof struct {
	*zk.ProofOfEqualOpenings
}

func (MaskedResharingProof) Type() ZkProofType {
	return ProofOfMaskedResharing
}
func (m MaskedResharingProof) Clone() ZkProof {
	return &MaskedResharingProof{
		m.ProofOfEqualOpenings.Clone(),
	}
}

type ProductProof struct {
	*zk.ProofOfProduct
}

func (ProductProof) Type() ZkProofType {
	return ProofOfMaskedResharing
}
func (p ProductProof) Clone() ZkProof {
	return &ProductProof{
		p.ProofOfProduct.Clone(),
	}
}
