package curve

import (
	"encoding/hex"
	"github.com/pkg/errors"
)

const (
	Identity        = Tag(0)
	CompressedEvenY = Tag(2)
	CompressedOddY  = Tag(3)
	Uncompressed    = Tag(4)
	Compact         = Tag(5)
)

type Tag uint8

func (t Tag) IsCompact() bool {
	return t == Compact
}
func (t Tag) IsCompressed() bool {
	return t == CompressedEvenY || t == CompressedOddY
}

func (t Tag) IsIdentity() bool {
	return t == Identity
}

func (t Tag) MessageLen(fieldElementSize int) int {
	length := 1
	switch t {
	case Identity:
	case CompressedEvenY, CompressedOddY:
		length += fieldElementSize
	case Uncompressed:
		length += fieldElementSize * 2
	case Compact:
		length += fieldElementSize
	}
	return length
}
func (t Tag) CompressY(y []byte) Tag {
	if y[len(y)-1]&1 == 1 {
		return CompressedOddY
	}
	return CompressedEvenY
}

type Coordinates interface {
	Tag() Tag
}

type IdentityCoordinates struct {
}

func (i IdentityCoordinates) Tag() Tag {
	return Identity
}

type CompactCoordinates struct {
	x []byte
}

func (c CompactCoordinates) Tag() Tag {
	return Compact
}

type CompressedCoordinates struct {
	x      []byte
	yIsOdd bool
}

func (c CompressedCoordinates) Tag() Tag {
	if c.yIsOdd {
		return CompressedOddY
	}
	return CompressedEvenY
}

type UnCompressedCoordinates struct {
	x []byte
	y []byte
}

func (c UnCompressedCoordinates) Tag() Tag {
	return Uncompressed
}

type EncodePoint interface {
	Len() int
	AsBytes() []byte
	ToString() string
	IsCompact() bool
	IsCompressed() bool
	IsIdentity() bool
	Compress() EncodePoint
	Coordinates() Coordinates
	X() []byte
	Y() []byte
	Tag() Tag
}

type EncodePoint32 struct {
	bytes []byte
}

var (
	Encode = encode32{}
)

type encode32 struct{}

func (e encode32) Default() EncodePoint {
	bytes := make([]byte, 32, 32)
	return &EncodePoint32{bytes: bytes}
}

func (e encode32) toSize() int {
	return 32
}

func (e encode32) FromBytes(input []byte) (EncodePoint, error) {
	tag := Tag(input[0])
	expected := tag.MessageLen(e.toSize())
	if len(input) != expected {
		return nil, errors.New("point decode failed")
	}
	bytes := make([]byte, expected, expected)
	copy(bytes, input)
	return &EncodePoint32{bytes: bytes}, nil
}

func (e encode32) FromStr(str string) (EncodePoint, error) {
	bytes, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return e.FromBytes(bytes)
}

func (e encode32) FromUnTaggedBytes(input []byte) EncodePoint {
	x, y := input[0:e.toSize()], input[e.toSize():]
	return e.FromAffineCoordinates(x, y, false)
}

func (e encode32) FromAffineCoordinates(x, y []byte, compress bool) EncodePoint {
	tag := Tag(0)
	if compress {
		tag = tag.CompressY(y)
	} else {
		tag = Uncompressed
	}
	bytes := make([]byte, 1+e.toSize()*2, 1+e.toSize()*2)
	bytes[0] = byte(tag)
	copy(bytes[1:e.toSize()+1], x)
	copy(bytes[e.toSize()+1:], y)
	return &EncodePoint32{bytes: bytes}
}

func (e encode32) Identity() EncodePoint {
	return &EncodePoint32{
		bytes: make([]byte, e.toSize()),
	}
}

func (e encode32) ConditionalSelect(a EncodePoint, b EncodePoint, choice int) EncodePoint {
	var bytes []byte
	if choice == 0 {
		bytes = make([]byte, len(a.(*EncodePoint32).bytes), len(a.(*EncodePoint32).bytes))
		copy(bytes, a.(*EncodePoint32).bytes)
	} else {
		bytes = make([]byte, len(b.(*EncodePoint32).bytes), len(b.(*EncodePoint32).bytes))
		copy(bytes, b.(*EncodePoint32).bytes)
	}
	return &EncodePoint32{bytes: bytes}
}

func (e EncodePoint32) Len() int {
	return e.Tag().MessageLen(encode32{}.toSize())
}

func (e EncodePoint32) AsBytes() []byte {
	return e.bytes[0:e.Len()]
}

func (e EncodePoint32) ToString() string {
	return hex.EncodeToString(e.bytes)
}

func (e EncodePoint32) IsCompact() bool {
	return e.Tag().IsCompact()
}

func (e EncodePoint32) IsCompressed() bool {
	return e.Tag().IsCompressed()
}

func (e EncodePoint32) IsIdentity() bool {
	return e.Tag().IsIdentity()
}

func (e EncodePoint32) Compress() EncodePoint {
	if e.IsCompact() || e.IsCompressed() || e.IsIdentity() {
		return &EncodePoint32{bytes: e.bytes}
	}
	encode := encode32{}
	x, y := e.bytes[1:encode.toSize()+1], e.bytes[encode.toSize()+1:]
	return encode.FromAffineCoordinates(x, y, true)
}

func (e EncodePoint32) Coordinates() Coordinates {
	if e.IsIdentity() {
		return IdentityCoordinates{}
	}
	encode := encode32{}
	x, y := e.bytes[1:encode.toSize()+1], e.bytes[encode.toSize()+1:]
	if e.IsCompressed() {
		return &CompressedCoordinates{
			x:      x,
			yIsOdd: uint8(e.Tag())&1 == 1,
		}
	} else if e.IsCompact() {
		return &CompactCoordinates{x: x}
	} else {
		return &UnCompressedCoordinates{
			x: x,
			y: y,
		}
	}

}

func (e EncodePoint32) X() []byte {
	var x []byte
	switch c := e.Coordinates().(type) {
	case *IdentityCoordinates:
		x = nil
	case *CompressedCoordinates:
		x = c.x
	case *UnCompressedCoordinates:
		x = c.x
	case *CompactCoordinates:
		x = c.x
	}
	return x
}

func (e EncodePoint32) Y() []byte {
	var y []byte
	switch c := e.Coordinates().(type) {
	case *IdentityCoordinates, *CompressedCoordinates, *CompactCoordinates:
		y = nil
	case *UnCompressedCoordinates:
		y = c.y
	}
	return y
}

func (e EncodePoint32) Tag() Tag {
	return Tag(e.bytes[0])
}
