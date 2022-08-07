package testutils

import (
	"fmt"
	"github.com/PlatONnetwork/tecdsa/common"
	complaints2 "github.com/PlatONnetwork/tecdsa/complaints"
	"github.com/PlatONnetwork/tecdsa/curve"
	dealings2 "github.com/PlatONnetwork/tecdsa/dealings"
	"github.com/PlatONnetwork/tecdsa/poly"
	seed2 "github.com/PlatONnetwork/tecdsa/seed"
	"github.com/pkg/errors"
	"github.com/tidwall/btree"
)

func OpenDealings(setup *ProtocolSetup, dealings *btree.Map[common.NodeIndex, *dealings2.IDkgDealingInternal], transcript *dealings2.IDkgTranscriptInternal) ([]poly.CommitmentOpening, error) {
	openings := make([]poly.CommitmentOpening, 0, setup.Receivers)
	reconstructionThreshold := setup.Threshold
	bytes, err := transcript.CombinedCommitment.Serialize()
	if err != nil {
		return nil, err
	}
	seed := seed2.FromBytes(bytes)
	rng := seed.Derive("rng").Rng()

	for receiver := 0; receiver < setup.Receivers; receiver++ {
		opening, err := dealings2.CommitmentOpening.FromDealings(dealings, transcript.CombinedCommitment, setup.Ad, common.NodeIndex(receiver), setup.Sk[receiver], setup.Pk[receiver])
		if err == nil {
			openings = append(openings, opening)
		} else {
			complaints, err := complaints2.GenerateComplaints(dealings, setup.Ad, common.NodeIndex(receiver), setup.Sk[receiver], setup.Pk[receiver], seed.Derive(fmt.Sprintf("complaint-%d", receiver)))
			if err != nil {
				return nil, err
			}
			var providedOpenings btree.Map[common.NodeIndex, *btree.Map[common.NodeIndex, poly.CommitmentOpening]]
			complaints.Scan(func(dealerIndex common.NodeIndex, complaint *complaints2.IDkgComplaintInternal) bool {
				dealing, ok := dealings.Get(dealerIndex)
				if !ok {
					err = errors.New("dealings non-exists")
					return false
				}
				if err = complaint.Verify(dealing, dealerIndex, common.NodeIndex(receiver), setup.Pk[receiver], setup.Ad); err != nil {
					return false
				}
				var openingsForThisDealing btree.Map[common.NodeIndex, poly.CommitmentOpening]
				sks, pks, openers := setup.ReceiverInfo()
				for i := 0; i < len(openers); i++ {
					sk, pk, opener := sks[i], pks[i], openers[i]
					if opener == common.NodeIndex(receiver) {
						continue
					}
					if err = dealing.PrivateVerify(curve.K256, sk, pk, setup.Ad, dealerIndex, opener); err != nil {
						continue
					}
					dopening, err := dealings2.CommitmentOpening.OpenDealing(dealing, setup.Ad, dealerIndex, opener, setup.Sk[opener], setup.Pk[opener])
					if err != nil {
						panic("unable to open dealing")
					}
					if dealing.Commitment.CheckOpening(opener, dopening) {
						err = errors.New("verify dealing opening failed")
						return false
					}
					openingsForThisDealing.Set(dealerIndex, dopening)
				}
				for openingsForThisDealing.Len() > reconstructionThreshold {
					index := int(rng.Uint32()) % openingsForThisDealing.Len()
					openingsForThisDealing.Delete(common.NodeIndex(index))
				}
				providedOpenings.Set(dealerIndex, &openingsForThisDealing)
				return true
			})
			if err != nil {
				return nil, err
			}
			opening, err = dealings2.CommitmentOpening.FromDealingsAndOpenings(dealings, &providedOpenings, transcript.CombinedCommitment, setup.Ad, common.NodeIndex(receiver), setup.Sk[receiver], setup.Pk[receiver])
			if err != nil {
				panic("unable to open dealing using provided openings")
			}
			openings = append(openings, opening)
		}
	}
	return openings, nil
}

func CreateDealings(setup *ProtocolSetup, shares []dealings2.SecretShares, numberOfDealers int, numberOfDealingsCorrupted int, transcriptType dealings2.IDkgTranscriptOperationInternal, seed *seed2.Seed) (*btree.Map[common.NodeIndex, dealings2.IDkgDealingInternal], error) {
	rng := seed.Rng()
	var dealings btree.Map[common.NodeIndex, *dealings2.IDkgDealingInternal]
	for i, share := range shares {
		dealerIndex := common.NodeIndex(i)
		dealing, err := dealings2.NewIDkgDealingInternal(share, curve.K256, seed2.FromRng(rng), setup.Threshold, setup.Pk, dealerIndex, setup.Ad)
		if err != nil {
			return nil, err
		}
		//todo testpublic
		sks, pks, recipients := setup.ReceiverInfo()
		for i := 0; i < len(recipients); i++ {
			sk, pk, recipient := sks[i], pks[i], recipients[i]
			if err := dealing.PrivateVerify(curve.K256, sk, pk, setup.Ad, dealerIndex, recipient); err != nil {
				return nil, err
			}
			dealings.Set(dealerIndex, dealing)
		}
		for dealings.Len() > numberOfDealers {
			index := int(rng.Uint32()) % dealings.Len()
			dealings.Delete(dealings.Keys()[index])
		}
		var dealingsToDamage btree.Map[common.NodeIndex, *dealings2.IDkgDealingInternal]
		for dealingsToDamage.Len() < numberOfDealingsCorrupted {
			index := int(rng.Uint32()) % dealings.Len()
			key := dealings.Keys()[index]
			value, _ := dealings.Get(key)
			dealingsToDamage.Set(key, value)
		}
		keys, values := dealingsToDamage.KeyValues()
		for i := 0; i < len(keys); i++ {

		}
	}
}
