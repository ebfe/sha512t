package sha512t

import (
	"testing"
)

var testInit = []struct {
	t int
	h []uint64
}{
	{
		t: 224,
		h: []uint64{
			0x8c3d37c819544da2,
			0x73e1996689dcd4d6,
			0x1dfab7ae32ff9c82,
			0x679dd514582f9fcf,
			0x0f6d2b697bd44da8,
			0x77e36f7304c48942,
			0x3f9d85a86a1d36c8,
			0x1112e6ad91d692a1,
		},
	}, {
		t: 256,
		h: []uint64{
			0x22312194fc2bf72c,
			0x9f555fa3c84c64c2,
			0x2393b86b6f53b151,
			0x963877195940eabd,
			0x96283ee2a88effe3,
			0xbe5e1e2553863992,
			0x2b0199fc2c85b8aa,
			0x0eb72ddc81c52ca2,
		},
	},
}

func TestInit(t *testing.T) {
	for _, tc := range testInit {
		s := New(tc.t).(*digest)
		for i := range s.h {
			if s.h[i] != tc.h[i] {
				t.Errorf("sha512/%d: h[%d] %x != %x\n", tc.t, i, s.h[i], tc.h[i])
				continue
			}
		}
	}
}
