package mega

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	ro2 "github.com/PlatONnetwork/tecdsa/ro"
	"github.com/PlatONnetwork/tecdsa/seed"
	"github.com/PlatONnetwork/tecdsa/zk"
)

const (
	CiphertextSingle = iota
	CiphertextPairs
)

func megaHashToScalars(ctype MEGaCiphertextType, dealerIndex common.NodeIndex, recipientIndex common.NodeIndex, associatedData []byte, publicKey, ephemeralKey, sharedSecret curve.EccPoint) ([]curve.EccScalar, error) {
	curveType := publicKey.CurveType()
	count := 1
	if ctype == CiphertextPairs {
		count = 2
	}
	ro := ro2.NewRandomOracle(ctype.EncryptionDomainSep())
	ro.AddUint32("dealer_index", uint32(dealerIndex))
	ro.AddUint32("recipient_index", uint32(recipientIndex))
	ro.AddBytesString("associated_data", associatedData)
	ro.AddPoint("public_key", publicKey)
	ro.AddPoint("ephemeral_key", ephemeralKey)
	ro.AddPoint("shared_secret", sharedSecret)
	return ro.OutputScalars(curveType, count)
}

/// Compute the Proof Of Possession (PoP) base element
///
/// This is used in conjuction with a DLOG equality ZK proof in order
/// for the sender to prove to recipients that it knew the discrete
/// log of the ephemeral key.
func ComputePopBase(ctype MEGaCiphertextType, curveType curve.EccCurveType, ad []byte, dealerIndex common.NodeIndex, ephemeralKey curve.EccPoint) (curve.EccPoint, error) {
	ro := ro2.NewRandomOracle(ctype.PopBaseDomainSep())
	ro.AddBytesString("associated_data", ad)
	ro.AddUint32("dealer_index", uint32(dealerIndex))
	ro.AddPoint("ephemeral_key", ephemeralKey)
	return ro.OutputPoint(curveType)
}

/// Verify the Proof Of Possession (PoP)
func VerifyPop(ctype MEGaCiphertextType, ad []byte, dealerIndex common.NodeIndex, ephemeralKey curve.EccPoint, popPublicKey curve.EccPoint, popProof *zk.ProofOfDLogEquivalence) error {
	curveType := ephemeralKey.CurveType()
	popBase, err := ComputePopBase(ctype, curveType, ad, dealerIndex, ephemeralKey)
	if err != nil {
		return err
	}
	return popProof.Verify(curve.Point.GeneratorG(curveType), popBase, ephemeralKey, popPublicKey, ad)
}

/// Compute the ephemeral key and associated Proof Of Possession
///
/// The ephemeral key (here, `v`) is simply an ECDH public key, whose secret key
/// is `beta`.
///
/// We also compute a proof of possession by hashing various information,
/// including the ephemeral key, to another elliptic curve point
/// (`pop_base`). We compute a scalar multipliction of the `pop_base` and
/// `beta`, producing `pop_public_key`. Finally we create a ZK proof that the
/// discrete logarithms of `pop_public_key` and `v` are the same value (`beta`)
/// in the respective bases.
func ComputeEphKeyAndPop(ctype MEGaCiphertextType, curveType curve.EccCurveType, seed *seed.Seed, ad []byte, dealerIndex common.NodeIndex) (curve.EccScalar, curve.EccPoint, curve.EccPoint, *zk.ProofOfDLogEquivalence, error) {
	beta := curve.Scalar.FromSeed(curveType, seed.Derive(ctype.EphemeralKeyDomainSep()))
	v := curve.Point.MulByG(beta)
	popBase, err := ComputePopBase(ctype, curveType, ad, dealerIndex, v)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	popPublicKey := popBase.Clone().ScalarMul(popBase, beta)
	popProof, err := zk.ProofOfDLogEquivalenceIns.Create(seed.Derive(ctype.PopProofDomainSep()), beta, curve.Point.GeneratorG(curveType), popBase, ad)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return beta, v, popPublicKey, popProof, nil
}
