package sha512t

import (
	"bytes"
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

var testDigest = []struct {
	t int
	m []byte
	h []byte
}{
	{
		t: 224,
		m: []byte("abc"),
		h: []byte{
			0x46, 0x34, 0x27, 0x0F, 0x70, 0x7B, 0x6A, 0x54,
			0xDA, 0xAE, 0x75, 0x30, 0x46, 0x08, 0x42, 0xE2,
			0x0E, 0x37, 0xED, 0x26, 0x5C, 0xEE, 0xE9, 0xA4,
			0x3E, 0x89, 0x24, 0xAA,
		},
	}, {
		t: 224,

		m: []byte("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
		h: []byte{
			0x23, 0xFE, 0xC5, 0xBB, 0x94, 0xD6, 0x0B, 0x23,
			0x30, 0x81, 0x92, 0x64, 0x0B, 0x0C, 0x45, 0x33,
			0x35, 0xD6, 0x64, 0x73, 0x4F, 0xE4, 0x0E, 0x72,
			0x68, 0x67, 0x4A, 0xF9,
		},
	}, {
		t: 256,
		m: []byte("abc"),
		h: []byte{
			0x53, 0x04, 0x8E, 0x26, 0x81, 0x94, 0x1E, 0xF9,
			0x9B, 0x2E, 0x29, 0xB7, 0x6B, 0x4C, 0x7D, 0xAB,
			0xE4, 0xC2, 0xD0, 0xC6, 0x34, 0xFC, 0x6D, 0x46,
			0xE0, 0xE2, 0xF1, 0x31, 0x07, 0xE7, 0xAF, 0x23,
		},
	}, {
		t: 256,

		m: []byte("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
		h: []byte{
			0x39, 0x28, 0xE1, 0x84, 0xFB, 0x86, 0x90, 0xF8,
			0x40, 0xDA, 0x39, 0x88, 0x12, 0x1D, 0x31, 0xBE,
			0x65, 0xCB, 0x9D, 0x3E, 0xF8, 0x3E, 0xE6, 0x14,
			0x6F, 0xEA, 0xC8, 0x61, 0xE1, 0x9B, 0x56, 0x3A,
		},
	},
}

func TestDigest(t *testing.T) {
	for _, tc := range testDigest {
		s := New(tc.t)
		s.Write(tc.m)
		h := s.Sum(nil)

		if !bytes.Equal(h, tc.h) {
			t.Errorf("sha512/%d: %q\n\texpected: %x\n\tgot:      %x\n", tc.t, string(tc.m), tc.h, h)
		}
	}
}
