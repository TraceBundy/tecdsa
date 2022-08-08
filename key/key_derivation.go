package key

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/pkg/errors"
	"hash"
	"math"
)

//func ReverseBytes(inBytes []byte) []byte {
//	outBytes := make([]byte, len(inBytes))
//
//	for i, j := 0, len(inBytes)-1; j >= 0; i, j = i+1, j-1 {
//		outBytes[i] = inBytes[j]
//	}
//
//	return outBytes
//}
func add(a, b uint8) (uint8, bool) {
	c := uint16(a) + uint16(b)
	if c > math.MaxUint8 {
		return 0, true
	}
	return uint8(c), false
}

type DerivationIndex []byte

func (d DerivationIndex) Next() DerivationIndex {
	n := common.ReverseBytes(d)
	carry := byte(1)
	for i, w := range n {
		v, c := add(w, carry)
		n[i] = v
		carry = 0
		if c {
			carry = 1
		}
	}
	if carry != 0 {
		n = append(n, carry)
	}
	return common.ReverseBytes(n)
}

type DerivationPath struct {
	path []DerivationIndex
}

func NewBip32(bip32 []uint32) *DerivationPath {
	path := make([]DerivationIndex, len(bip32), len(bip32))
	for i, n := range bip32 {
		var index [4]byte
		binary.BigEndian.PutUint32(index[:], n)
		path[i] = index[:]
	}
	return New(path)
}
func New(path []DerivationIndex) *DerivationPath {
	return &DerivationPath{path: path}
}

/// BIP32 Public parent key -> public child key (aka CKDpub)
///
/// See <https://en.bitcoin.it/wiki/BIP_0032#Child_key_derivation_.28CKD.29_functions>
///
/// Extended to support larger inputs, which is needed for
/// deriving the canister public key
func ckdpub(pk curve.EccPoint, chainKey []byte, index DerivationIndex) (curve.EccPoint, []byte, curve.EccScalar, error) {
	output, err := ComputeHMAC(crypto.SHA512.New, chainKey, pk.Serialize(), index)
	if err != nil {
		return nil, nil, nil, err
	}
	keyOffset, err := curve.Scalar.FromBytesWide(pk.CurveType(), output[:32])
	if err != nil {
		return nil, nil, nil, err
	}
	newChainKey := output[32:]
	newKey := pk.Clone().AddPoints(pk, curve.Point.MulByG(keyOffset))
	if !bytes.Equal(keyOffset.Serialize(), output[:32]) || newKey.IsInfinity() {
		ckdpub(pk, chainKey, index.Next())
	}
	return newKey, newChainKey, keyOffset, nil
}

func (d *DerivationPath) DeriveTweak(pk curve.EccPoint) (curve.EccScalar, []byte, error) {
	curveType := pk.CurveType()
	if curveType != curve.K256 {
		return nil, nil, errors.New("invalid curve type")
	}
	derivedKey := pk.Clone()
	empty := [32]byte{}
	var derivedChainKey []byte
	derivedChainKey = empty[:]
	derivedOffset := curve.Scalar.Zero(curveType)
	for _, idx := range d.path {
		nextDerivedKey, nextChainKey, nextOffset, err := ckdpub(derivedKey, derivedChainKey[:], idx)
		if err != nil {
			return nil, nil, err
		}
		derivedKey, derivedChainKey, derivedOffset = nextDerivedKey, nextChainKey, derivedOffset.Add(derivedOffset, nextOffset)
	}
	return derivedOffset, derivedChainKey, nil
}

func ComputeHMAC(f func() hash.Hash, k []byte, msg ...[]byte) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("hash function cannot be nil")
	}

	mac := hmac.New(f, k)
	for _, m := range msg {
		w, err := mac.Write(m)
		if w != len(msg) {
			return nil, fmt.Errorf("bytes written to hash doesn't match expected: %v != %v", w, len(msg))
		} else if err != nil {
			return nil, err
		}
	}

	return mac.Sum(nil), nil
}
