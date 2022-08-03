package mega

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/poly"
	"github.com/PlatONnetwork/tecdsa/seed"
	"github.com/PlatONnetwork/tecdsa/zk"
	"github.com/pkg/errors"
)

type MEGaCiphertextType int

func (m MEGaCiphertextType) EncryptionDomainSep() string {
	switch m {
	case CiphertextSingle:
		return "ic-crypto-tecdsa-mega-encryption-single-encrypt"
	case CiphertextPairs:
		return "ic-crypto-tecdsa-mega-encryption-pair-encrypt"
	}
	return ""
}

func (m MEGaCiphertextType) PopBaseDomainSep() string {
	switch m {
	case CiphertextSingle:
		return "ic-crypto-tecdsa-mega-encryption-single-pop-base"
	case CiphertextPairs:
		return "ic-crypto-tecdsa-mega-encryption-pair-pop-base"
	}
	return ""
}

func (m MEGaCiphertextType) PopProofDomainSep() string {
	switch m {
	case CiphertextSingle:
		return "ic-crypto-tecdsa-mega-encryption-single-pop-proof"
	case CiphertextPairs:
		return "ic-crypto-tecdsa-mega-encryption-pair-pop-proof"
	}
	return ""
}

func (m MEGaCiphertextType) EphemeralKeyDomainSep() string {
	switch m {
	case CiphertextSingle:
		return "ic-crypto-tecdsa-mega-encryption-single-ephemeral-key"
	case CiphertextPairs:
		return "ic-crypto-tecdsa-mega-encryption-pair-ephemeral-key"
	}
	return ""
}

type MEGaCiphertext interface {
	Recipients() int
	CType() MEGaCiphertextType
	Ephemeral() curve.EccPoint
	PopPublic() curve.EccPoint
	Proof() *zk.ProofOfDLogEquivalence
	CheckValidity() error
	DecryptAndCheck(commitment poly.PolynomialCommitment, ad []byte, dealerIndex common.NodeIndex, receiverIndex common.NodeIndex, secretKey *MEGaPrivateKey, publicKey *MEGaPublicKey) (poly.CommitmentOpening, error)
}

func EncryptCiphertextSingle(seed *seed.Seed, plaintexts []curve.EccScalar, recipients []*MEGaPublicKey, dealerIndex common.NodeIndex, ad []byte) (*MEGaCiphertextSingle, error) {
	if err := checkPlaintexts(plaintexts, recipients); err != nil {
		return nil, err
	}

	beta, v, popPublicKey, popProof, err := ComputeEphKeyAndPop(CiphertextSingle, plaintexts[0].CurveType(), seed, ad, dealerIndex)
	if err != nil {
		return nil, err
	}
	ctexts := make([]curve.EccScalar, len(recipients))
	for index := 0; index < len(recipients); index++ {
		pubkey, ptext := recipients[index], plaintexts[index]
		ubeta := pubkey.point.Clone().ScalarMul(pubkey.point, beta)
		hm, err := megaHashToScalars(CiphertextSingle, dealerIndex, common.NodeIndex(index), ad, pubkey.point, v, ubeta)
		if err != nil {
			return nil, err
		}
		ctext := hm[0].Add(hm[0], ptext)
		ctexts[index] = ctext
	}
	return &MEGaCiphertextSingle{
		EphemeralKey: v,
		PopPublicKey: popPublicKey,
		PopProof:     popProof,
		CTexts:       ctexts,
	}, nil
}

func checkPlaintexts(plaintexts []curve.EccScalar, recipients []*MEGaPublicKey) error {
	if len(plaintexts) != len(recipients) {
		return errors.New("Must be as many plaintexts as recipients")
	}
	if len(plaintexts) == 0 {
		return errors.New("Must encrypt at least one plaintext")
	}
	curveType := plaintexts[0].CurveType()
	for i := range plaintexts {
		if plaintexts[i].CurveType() != curveType {
			return errors.New("curve type mismatch")
		}
	}
	for i := range recipients {
		if recipients[i].CurveType() != curveType {
			return errors.New("curve type mismatch")
		}
	}
	return nil
}

func checkPlaintextsPair(plaintexts [][2]curve.EccScalar, recipients []*MEGaPublicKey) error {
	if len(plaintexts) != len(recipients) {
		return errors.New("Must be as many plaintexts as recipients")
	}
	if len(plaintexts) == 0 {
		return errors.New("Must encrypt at least one plaintext")
	}
	curveType := plaintexts[0][0].CurveType()
	for i := range plaintexts {
		if plaintexts[i][0].CurveType() != curveType || plaintexts[i][1].CurveType() != curveType {
			return errors.New("curve type mismatch")
		}
	}
	for i := range recipients {
		if recipients[i].CurveType() != curveType {
			return errors.New("curve type mismatch")
		}
	}
	return nil
}

type MEGaCiphertextSingle struct {
	EphemeralKey curve.EccPoint
	PopPublicKey curve.EccPoint
	PopProof     *zk.ProofOfDLogEquivalence
	CTexts       []curve.EccScalar
}

func (m MEGaCiphertextSingle) Clone() *MEGaCiphertextSingle {
	ctexts := make([]curve.EccScalar, len(m.CTexts), len(m.CTexts))
	for i, c := range m.CTexts {
		ctexts[i] = c.Clone()
	}
	return &MEGaCiphertextSingle{
		EphemeralKey: m.EphemeralKey.Clone(),
		PopPublicKey: m.PopPublicKey.Clone(),
		PopProof:     m.PopProof.Clone(),
		CTexts:       ctexts,
	}
}

func (m MEGaCiphertextSingle) Recipients() int {
	return len(m.CTexts)
}

func (m MEGaCiphertextSingle) CType() MEGaCiphertextType {
	return CiphertextSingle
}

func (m MEGaCiphertextSingle) Ephemeral() curve.EccPoint {
	return m.EphemeralKey
}

func (m MEGaCiphertextSingle) PopPublic() curve.EccPoint {
	return m.PopPublicKey
}

func (m MEGaCiphertextSingle) Proof() *zk.ProofOfDLogEquivalence {
	return m.PopProof
}

func (m MEGaCiphertextSingle) CheckValidity(expectedRecipients int, ad []byte, dealerIndex common.NodeIndex) error {
	if m.Recipients() != expectedRecipients {
		return errors.New("invalid recipients")
	}
	return m.VerifyPop(ad, dealerIndex)
}

func (m MEGaCiphertextSingle) VerifyPop(ad []byte, dealerIndex common.NodeIndex) error {
	return VerifyPop(CiphertextSingle, ad, dealerIndex, m.EphemeralKey, m.PopPublicKey, m.PopProof)
}

func (m MEGaCiphertextSingle) DecryptFromSharedSecret(ad []byte, dealerIndex common.NodeIndex, recipientIndex common.NodeIndex, recipientPublicKey *MEGaPublicKey, sharedSecret curve.EccPoint) (curve.EccScalar, error) {
	if len(m.CTexts) <= int(recipientIndex) {
		return nil, errors.New("invalid index")
	}
	hm, err := megaHashToScalars(CiphertextSingle, dealerIndex, recipientIndex, ad, recipientPublicKey.point, m.EphemeralKey, sharedSecret)
	if err != nil {
		return nil, err
	}
	return m.CTexts[int(recipientIndex)].Clone().Sub(m.CTexts[int(recipientIndex)], hm[0]), nil
}
func (m MEGaCiphertextSingle) Decrypt(ad []byte, dealerIndex common.NodeIndex, recipientIndex common.NodeIndex, privateKey *MEGaPrivateKey, recipientPublicKey *MEGaPublicKey) (curve.EccScalar, error) {
	if err := m.VerifyPop(ad, dealerIndex); err != nil {
		return nil, err
	}
	ubeta := m.EphemeralKey.Clone().ScalarMul(m.EphemeralKey, privateKey.secret)
	return m.DecryptFromSharedSecret(ad, dealerIndex, recipientIndex, recipientPublicKey, ubeta)
}
func (m MEGaCiphertextSingle) DecryptAndCheck(commitment poly.PolynomialCommitment, ad []byte, dealerIndex common.NodeIndex, receiverIndex common.NodeIndex, secretKey *MEGaPrivateKey, publicKey *MEGaPublicKey) (poly.CommitmentOpening, error) {
	scalar, err := m.Decrypt(ad, dealerIndex, receiverIndex, secretKey, publicKey)
	if err != nil {
		return nil, err
	}
	opening := &poly.SimpleCommitmentOpening{scalar}
	if !commitment.CheckOpening(receiverIndex, opening) {
		return nil, errors.New("invalid commitment")
	}
	return opening, nil
}

type MEGaCiphertextPair struct {
	EphemeralKey curve.EccPoint
	PopPublicKey curve.EccPoint
	PopProof     *zk.ProofOfDLogEquivalence
	CTexts       [][2]curve.EccScalar
}

func EncryptCiphertextPair(seed *seed.Seed, plaintexts [][2]curve.EccScalar, recipients []*MEGaPublicKey, dealerIndex common.NodeIndex, ad []byte) (*MEGaCiphertextPair, error) {
	if err := checkPlaintextsPair(plaintexts, recipients); err != nil {
		return nil, err
	}
	beta, v, popPublicKey, popProof, err := ComputeEphKeyAndPop(CiphertextPairs, plaintexts[0][0].CurveType(), seed, ad, dealerIndex)
	if err != nil {
		return nil, err
	}
	ctexts := make([][2]curve.EccScalar, len(recipients))
	for index := 0; index < len(recipients); index++ {
		pubkey, ptext := recipients[index], plaintexts[index]
		ubeta := pubkey.point.Clone().ScalarMul(pubkey.point, beta)
		hm, err := megaHashToScalars(CiphertextPairs, dealerIndex, common.NodeIndex(index), ad, pubkey.point, v, ubeta)
		if err != nil {
			return nil, err
		}
		ctext0 := hm[0].Add(hm[0], ptext[0])
		ctext1 := hm[1].Add(hm[1], ptext[1])
		ctexts[index] = [2]curve.EccScalar{ctext0, ctext1}
	}
	return &MEGaCiphertextPair{
		EphemeralKey: v,
		PopPublicKey: popPublicKey,
		PopProof:     popProof,
		CTexts:       ctexts,
	}, nil
}

func (m MEGaCiphertextPair) Recipients() int {
	return len(m.CTexts)
}

func (MEGaCiphertextPair) CType() MEGaCiphertextType {
	return CiphertextPairs
}

func (m MEGaCiphertextPair) GetEphemeralKey() curve.EccPoint {
	return m.EphemeralKey
}

func (m MEGaCiphertextPair) GetPopPublicKey() curve.EccPoint {
	return m.PopPublicKey
}

func (m MEGaCiphertextPair) GetPopProof() *zk.ProofOfDLogEquivalence {
	return m.PopProof
}

func (m MEGaCiphertextPair) VerifyPop(ad []byte, dealerIndex common.NodeIndex) error {
	return VerifyPop(CiphertextPairs, ad, dealerIndex, m.EphemeralKey, m.PopPublicKey, m.PopProof)
}

func (m MEGaCiphertextPair) DecryptFromSharedSecret(ad []byte, dealerIndex common.NodeIndex, recipientIndex common.NodeIndex, recipientPublicKey *MEGaPublicKey, sharedSecret curve.EccPoint) ([2]curve.EccScalar, error) {
	if len(m.CTexts) <= int(recipientIndex) {
		return [2]curve.EccScalar{}, errors.New("invalid index")
	}
	hm, err := megaHashToScalars(CiphertextPairs, dealerIndex, recipientIndex, ad, recipientPublicKey.point, m.EphemeralKey, sharedSecret)
	if err != nil {
		return [2]curve.EccScalar{}, err
	}
	ptext0 := m.CTexts[int(recipientIndex)][0].Clone().Sub(m.CTexts[int(recipientIndex)][0], hm[0])
	ptext1 := m.CTexts[int(recipientIndex)][1].Clone().Sub(m.CTexts[int(recipientIndex)][1], hm[1])
	return [2]curve.EccScalar{ptext0, ptext1}, nil

}
func (m MEGaCiphertextPair) Decrypt(ad []byte, dealerIndex common.NodeIndex, recipientIndex common.NodeIndex, privateKey *MEGaPrivateKey, recipientPublicKey *MEGaPublicKey) ([2]curve.EccScalar, error) {
	if err := m.VerifyPop(ad, dealerIndex); err != nil {
		return [2]curve.EccScalar{}, err
	}
	ubeta := m.EphemeralKey.Clone().ScalarMul(m.EphemeralKey, privateKey.secret)
	return m.DecryptFromSharedSecret(ad, dealerIndex, recipientIndex, recipientPublicKey, ubeta)
}

func (m MEGaCiphertextPair) CheckValidity(expectedRecipients int, ad []byte, dealerIndex common.NodeIndex) error {
	if m.Recipients() != expectedRecipients {
		return errors.New("invalid recipients")
	}
	return m.VerifyPop(ad, dealerIndex)
}

func (m MEGaCiphertextPair) DecryptAndCheck(commitment poly.PolynomialCommitment, ad []byte, dealerIndex common.NodeIndex, receiverIndex common.NodeIndex, secretKey *MEGaPrivateKey, publicKey *MEGaPublicKey) (poly.CommitmentOpening, error) {
	scalar, err := m.Decrypt(ad, dealerIndex, receiverIndex, secretKey, publicKey)
	if err != nil {
		return nil, err
	}
	opening := &poly.PedersenCommitmentOpening{}
	opening[1] = scalar[0]
	opening[1] = scalar[1]
	if !commitment.CheckOpening(receiverIndex, opening) {
		return nil, errors.New("invalid commitment")
	}
	return opening, nil
}
