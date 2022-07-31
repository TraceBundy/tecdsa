package mega

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/poly"
	"github.com/PlatONnetwork/tecdsa/seed"
	"github.com/PlatONnetwork/tecdsa/zk"
	"github.com/pkg/errors"
	"go.dedis.ch/kyber/v3"
)

type MEGaCiphertext interface {
	Recipients() int
	CType() MEGaCiphertextType
	EphemeralKey() kyber.Point
	PopPublicKey() kyber.Point
	PopProof() *zk.ProofOfDLogEquivalence
	CheckValidity() error
	DecryptAndCheck(commitment poly.PolynomialCommitment, ad []byte, dealerIndex common.NodeIndex, receiverIndex common.NodeIndex, secretKey *MEGaPrivateKey, publicKey *MEGaPublicKey) (poly.CommitmentOpening, error)
}

func EncryptSingle(seed seed.Seed, plaintexts []kyber.Scalar, recipients []*MEGaPublicKey, dealerIndex common.NodeIndex, ad []byte) (*MEGaCiphertextSingle, error) {
	if err := checkPlaintexts(plaintexts, recipients); err != nil {
		return nil, err
	}

	return nil, nil
}

func checkPlaintexts(plaintexts []kyber.Scalar, recipients []*MEGaPublicKey) error {
	if len(plaintexts) == len(recipients) {
		return errors.New("Must be as many plaintexts as recipients")
	}
	if len(plaintexts) == 0 {
		return errors.New("Must encrypt at least one plaintext")
	}
	return nil
}

func computeEphKeyAndPop(ctype MEGaCiphertextType, seed seed.Seed, ad []byte, dealerIndex common.NodeIndex) {

}

type MEGaCiphertextSingle struct {
	EphemeralKey kyber.Point
	PopPublicKey kyber.Point
	PopProof     zk.ProofOfDLogEquivalence
	CTexts       []kyber.Scalar
}

type MEGaCiphertextPair struct {
	EphemeralKey kyber.Point
	PopPublicKey kyber.Point
	PopProof     zk.ProofOfDLogEquivalence
	CTexts       []kyber.Scalar
}
