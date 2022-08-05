package zk

import (
	"github.com/PlatONnetwork/tecdsa/curve"
	ro2 "github.com/PlatONnetwork/tecdsa/ro"
	"github.com/PlatONnetwork/tecdsa/seed"
	"github.com/pkg/errors"
)

const (
	ProofOfDlogEquivDst     = "ic-crypto-tecdsa-zk-proof-of-dlog-eq"
	ProofOfEqualOpeningsDst = "ic-crypto-tecdsa-zk-proof-of-equal-openings"
	ProofOfProductDst       = "ic-crypto-tecdsa-zk-proof-of-product"
)

var (
	ProofOfEqualOpeningsIns = proofOfEqualOpeningsInstance{}
)

type ProofOfEqualOpenings struct {
	challenge curve.EccScalar
	response  curve.EccScalar
}

type ProofOfEqualOpeningsInstance struct {
	curveType curve.EccCurveType
	g         curve.EccPoint
	h         curve.EccPoint
	a         curve.EccPoint
	b         curve.EccPoint
}

type proofOfEqualOpeningsInstance struct{}

func (proofOfEqualOpeningsInstance) FromWitness(secret curve.EccScalar, masking curve.EccScalar) *ProofOfEqualOpeningsInstance {
	curveType := secret.CurveType()
	g := curve.Point.GeneratorG(curveType)
	h := curve.Point.GeneratorH(curveType)
	a := curve.Point.Pedersen(secret, masking)
	b := curve.Point.MulByG(secret)
	return &ProofOfEqualOpeningsInstance{
		curveType,
		g,
		h,
		a,
		b,
	}
}

func (proofOfEqualOpeningsInstance) FromCommitments(pedersen curve.EccPoint, simple curve.EccPoint) *ProofOfEqualOpeningsInstance {
	curveType := pedersen.CurveType()
	g := curve.Point.GeneratorG(curveType)
	h := curve.Point.GeneratorH(curveType)
	return &ProofOfEqualOpeningsInstance{
		curveType: curveType,
		g:         g,
		h:         h,
		a:         pedersen.Clone(),
		b:         simple.Clone(),
	}
}

func (p proofOfEqualOpeningsInstance) Create(seed *seed.Seed, secret curve.EccScalar, masking curve.EccScalar, associatedData []byte) (*ProofOfEqualOpenings, error) {
	/*
	 * a = g^s · h^m, b = g^s
	 * com = h^r
	 * challenge = H(com,ad)
	 * response = (m · challenge) + r
	 */
	instance := p.FromWitness(secret, masking)
	r := curve.Scalar.Random(instance.curveType, seed.Rng())
	rcom := instance.h.Clone().ScalarMul(instance.h, r)
	challenge, err := instance.HashToChallenge(rcom, associatedData)
	if err != nil {
		return nil, err
	}
	response := masking.Clone().Mul(masking, challenge)
	response = response.Add(response, r)
	return &ProofOfEqualOpenings{
		challenge: challenge,
		response:  response,
	}, nil
}

func (p *ProofOfEqualOpeningsInstance) RecoverCommitments(proof *ProofOfEqualOpenings) curve.EccPoint {
	/*
	 * a = g^s · h^m, b = g^s
	 * com = h^r
	 * challenge = H(com,ad)
	 * response = (m · challenge) + r
	 * amb = a-b
	 * camb = amb * challenge
	 * hc = h^response
	 * com = h^((m · challenge) + r) - (g^s · h^m-g^s)^challenge
	 */
	amb := p.a.Clone().SubPoints(p.a, p.b)
	camb := amb.Clone().ScalarMul(amb, proof.challenge)
	hc := p.h.Clone().ScalarMul(p.h, proof.response)
	return hc.SubPoints(hc, camb)
}

func (p *ProofOfEqualOpeningsInstance) HashToChallenge(commitment curve.EccPoint, ad []byte) (curve.EccScalar, error) {
	ro := ro2.NewRandomOracle(ProofOfEqualOpeningsDst)
	ro.AddBytesString("associated_data", ad)
	ro.AddPoint("instance_g", p.g)
	ro.AddPoint("instance_h", p.h)
	ro.AddPoint("instance_a", p.a)
	ro.AddPoint("instance_b", p.b)
	ro.AddPoint("commitment", commitment)
	return ro.OutputScalar(p.curveType)
}

func (p *ProofOfEqualOpenings) Verify(pedersen curve.EccPoint, simple curve.EccPoint, associatedData []byte) error {
	instance := ProofOfEqualOpeningsIns.FromCommitments(pedersen, simple)
	rcom := instance.RecoverCommitments(p)
	challenge, err := instance.HashToChallenge(rcom, associatedData)
	if err != nil {
		return err
	}
	if p.challenge.Equal(challenge) == 0 {
		return errors.New("invalid proof")
	}
	return err
}

func (p *ProofOfEqualOpenings) Clone() *ProofOfEqualOpenings {
	return &ProofOfEqualOpenings{
		challenge: p.challenge.Clone(),
		response:  p.response.Clone(),
	}
}
