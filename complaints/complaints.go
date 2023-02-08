package complaints

import (
	"fmt"
	"github.com/TraceBundy/tecdsa/common"
	"github.com/TraceBundy/tecdsa/curve"
	"github.com/TraceBundy/tecdsa/dealings"
	"github.com/TraceBundy/tecdsa/mega"
	poly2 "github.com/TraceBundy/tecdsa/poly"
	ro2 "github.com/TraceBundy/tecdsa/ro"
	"github.com/TraceBundy/tecdsa/seed"
	"github.com/TraceBundy/tecdsa/zk"
	"github.com/pkg/errors"
	"github.com/tidwall/btree"
)

type IDkgComplaintInternal struct {
	proof        *zk.ProofOfDLogEquivalence
	sharedSecret curve.EccPoint
}

func GenerateComplaints(verifiedDealings *btree.Map[common.NodeIndex, *dealings.IDkgDealingInternal], ad []byte, receiverIndex common.NodeIndex, secretKey *mega.MEGaPrivateKey, publicKey *mega.MEGaPublicKey, seed *seed.Seed) (*btree.Map[common.NodeIndex, *IDkgComplaintInternal], error) {
	var complaints btree.Map[common.NodeIndex, *IDkgComplaintInternal]
	var err error
	verifiedDealings.Scan(func(dealerIndex common.NodeIndex, dealing *dealings.IDkgDealingInternal) bool {
		_, err = dealing.Ciphertext.DecryptAndCheck(dealing.Commitment, ad, dealerIndex, receiverIndex, secretKey, publicKey)
		if err != nil {
			var complaint *IDkgComplaintInternal
			complaintSeed := seed.Derive(fmt.Sprintf("ic-crypto-tecdsa-complaint-against-%d", dealerIndex))
			if complaint, err = NewComplaintInternal(complaintSeed, dealing, dealerIndex, receiverIndex, secretKey, publicKey, ad); err != nil {
				return false
			}
			complaints.Set(dealerIndex, complaint)
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	if complaints.Len() == 0 {
		return nil, errors.New("generate_complaints should return at least one complaint")
	}
	return &complaints, nil
}

func NewComplaintInternal(seed *seed.Seed, dealing *dealings.IDkgDealingInternal, dealerIndex common.NodeIndex, receiverIndex common.NodeIndex, secretKey *mega.MEGaPrivateKey, publicKey *mega.MEGaPublicKey, ad []byte) (*IDkgComplaintInternal, error) {
	sharedSecret := dealing.Ciphertext.Ephemeral().Clone().ScalarMul(dealing.Ciphertext.Ephemeral(), secretKey.SecretScalar())
	proofAssocData, err := createProofAssocData(ad, receiverIndex, dealerIndex, publicKey)
	if err != nil {
		return nil, err
	}
	proof, err := zk.ProofOfDLogEquivalenceIns.Create(seed, secretKey.SecretScalar(), curve.Point.GeneratorG(secretKey.SecretScalar().CurveType()), dealing.Ciphertext.Ephemeral(), proofAssocData)
	if err != nil {
		return nil, err
	}
	return &IDkgComplaintInternal{
		sharedSecret: sharedSecret,
		proof:        proof,
	}, nil
}

func createProofAssocData(ad []byte, receiverIndex common.NodeIndex, dealerIndex common.NodeIndex, publicKey *mega.MEGaPublicKey) ([]byte, error) {
	ro := ro2.NewRandomOracle("ic-crypto-tecdsa-complaint-proof-assoc-data")
	ro.AddBytesString("associated_data", ad)
	ro.AddUint32("receiver_index", uint32(receiverIndex))
	ro.AddUint32("dealer_index", uint32(dealerIndex))
	ro.AddPoint("receiver_public_key", publicKey.PublicPoint())
	return ro.OutputByteString(32)
}

func (c IDkgComplaintInternal) Verify(dealing *dealings.IDkgDealingInternal, dealerIndex, complainerIndex common.NodeIndex, complainerKey *mega.MEGaPublicKey, ad []byte) error {
	proofAssocData, err := createProofAssocData(ad, complainerIndex, dealerIndex, complainerKey)
	if err != nil {
		return err
	}
	if err := c.proof.Verify(curve.Point.GeneratorG(c.sharedSecret.CurveType()), dealing.Ciphertext.Ephemeral(), complainerKey.PublicPoint(), c.sharedSecret, proofAssocData); err != nil {
		return err
	}
	var commitOpening poly2.CommitmentOpening
	if s, ok := dealing.Ciphertext.(*mega.MEGaCiphertextSingle); ok && dealing.Commitment.Type() == poly2.Simple {
		opening, err := s.DecryptFromSharedSecret(ad, dealerIndex, complainerIndex, complainerKey, c.sharedSecret)
		if err != nil {
			return err
		}
		commitOpening = poly2.SimpleCommitmentOpening{opening}
	} else if s, ok := dealing.Ciphertext.(*mega.MEGaCiphertextPair); ok && dealing.Commitment.Type() == poly2.Pedersen {
		opening, err := s.DecryptFromSharedSecret(ad, dealerIndex, complainerIndex, complainerKey, c.sharedSecret)
		if err != nil {
			return err
		}
		commitOpening = poly2.PedersenCommitmentOpening([2]curve.EccScalar{opening[0], opening[1]})
	} else {
		return errors.New("unexpected commitment type")
	}

	if dealing.Commitment.CheckOpening(complainerIndex, commitOpening) {
		return errors.New("invalid complaint")
	}
	return nil
}
