package zk

import (
	"github.com/PlatONnetwork/tecdsa/curve"
	ro2 "github.com/PlatONnetwork/tecdsa/ro"
	"github.com/PlatONnetwork/tecdsa/seed"
	"github.com/pkg/errors"
)

var (
	ProofOfDLogEquivalenceIns = proofOfDLogEquivalenceInstance{}
)

type proofOfDLogEquivalenceInstance struct {
}
type ProofOfDLogEquivalence struct {
	challenge curve.EccScalar
	response  curve.EccScalar
}

type ProofOfDLogEquivalenceInstance struct {
	curveType curve.EccCurveType
	g         curve.EccPoint
	h         curve.EccPoint
	gx        curve.EccPoint
	hx        curve.EccPoint
}

func (proofOfDLogEquivalenceInstance) FromWitness(g curve.EccPoint, h curve.EccPoint, x curve.EccScalar) (*ProofOfDLogEquivalenceInstance, error) {
	gx := g.Clone().ScalarMul(g, x)
	hx := h.Clone().ScalarMul(h, x)
	return &ProofOfDLogEquivalenceInstance{
		curveType: x.CurveType(),
		g:         g,
		h:         h,
		gx:        gx,
		hx:        hx,
	}, nil
}

func (proofOfDLogEquivalenceInstance) FromCommitments(g curve.EccPoint, h curve.EccPoint, gx curve.EccPoint, hx curve.EccPoint) (*ProofOfDLogEquivalenceInstance, error) {
	return &ProofOfDLogEquivalenceInstance{
		curveType: g.CurveType(),
		g:         g,
		h:         h,
		gx:        gx,
		hx:        hx,
	}, nil
}

func (p *ProofOfDLogEquivalenceInstance) RecoverCommitments(proof *ProofOfDLogEquivalence) (curve.EccPoint, curve.EccPoint, error) {
	gz := p.g.Clone().ScalarMul(p.g, proof.response)
	hz := p.h.ScalarMul(p.h, proof.response)
	gr := gz.SubPoints(gz, p.gx.Clone().ScalarMul(p.gx, proof.challenge))
	hr := hz.SubPoints(hz, p.hx.ScalarMul(p.hx, proof.challenge))
	return gr, hr, nil
}

func (p *ProofOfDLogEquivalenceInstance) HashToChallenge(c1 curve.EccPoint, c2 curve.EccPoint, associatedData []byte) (curve.EccScalar, error) {
	ro := ro2.NewRandomOracle(ProofOfDlogEquivDst)
	ro.AddBytesString("associated_data", associatedData)
	ro.AddPoint("instance_g", p.g)
	ro.AddPoint("instance_h", p.h)
	ro.AddPoint("instance_g_x", p.gx)
	ro.AddPoint("instance_h_x", p.hx)
	ro.AddPoint("commitment1", c1)
	ro.AddPoint("commitment2", c2)
	return ro.OutputScalar(p.curveType)
}
func (p *proofOfDLogEquivalenceInstance) Create(seed seed.Seed, x curve.EccScalar, g, h curve.EccPoint, associatedData []byte) (*ProofOfDLogEquivalence, error) {
	instance, err := p.FromWitness(g, h, x)
	if err != nil {
		return nil, err
	}
	r := curve.Scalar.Random(instance.curveType, seed.Rng())
	rG := g.Clone().ScalarMul(g, r)
	rH := h.Clone().ScalarMul(h, r)
	challenge, err := instance.HashToChallenge(rG, rH, associatedData)
	response := x.Clone().Mul(x, challenge)
	response = response.Add(response, r)
	return &ProofOfDLogEquivalence{
		challenge: challenge,
		response:  response,
	}, nil
}

func (p *ProofOfDLogEquivalence) Verify(g, h, gx, hx curve.EccPoint, associatedData []byte) error {
	instance, err := ProofOfDLogEquivalenceIns.FromCommitments(g, h, gx, hx)
	if err != nil {
		return err
	}
	rG, rH, err := instance.RecoverCommitments(p)
	if err != nil {
		return err
	}
	challenge, err := instance.HashToChallenge(rG, rH, associatedData)
	if err != nil {
		return err
	}
	if challenge.Equal(p.challenge) == 0 {
		return errors.New("invalid proof")
	}
	return nil
}

func (p *ProofOfDLogEquivalence) CurveType() curve.EccCurveType {
	return p.challenge.CurveType()
}
