package key

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIndexNextBehavior(t *testing.T) {
	checkNext := func(input, output []byte) {
		index := DerivationIndex(input)
		next := index.Next()
		assert.Equal(t, output, []byte(next))
	}
	checkNext([]byte{}, []byte{1})
	checkNext([]byte{1}, []byte{2})
	checkNext([]byte{0xff}, []byte{1, 0})
	checkNext([]byte{0, 0, 0, 5}, []byte{0, 0, 0, 6})
	checkNext([]byte{0x7F, 0xFF, 0xFF, 0xFF}, []byte{0x80, 0x00, 0x00, 0x00})
}
