module github.com/PlatONnetwork/tecdsa

go 1.16

require (
	github.com/coinbase/kryptology v1.8.0
	github.com/ethereum/go-ethereum v1.10.16
	github.com/fxamacker/cbor/v2 v2.4.0
	github.com/magiconair/properties v1.8.5
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.0
	go.dedis.ch/kyber/v3 v3.0.13
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
	golang.org/x/sys v0.0.0-20220319134239-a9b59b0215f8 // indirect
	modernc.org/mathutil v1.4.1
)

replace github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1
