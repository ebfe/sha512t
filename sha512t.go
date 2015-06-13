// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha512t implements the SHA512/t hash algorithms as defined
// in FIPS 180-4.
package sha512t

import (
	"hash"
	"strconv"
)

// The blocksize of SHA512/t in bytes.
const BlockSize = 128

const (
	chunk      = 128
	init0      = 0x6a09e667f3bcc908 ^ 0xa5a5a5a5a5a5a5a5
	init1      = 0xbb67ae8584caa73b ^ 0xa5a5a5a5a5a5a5a5
	init2      = 0x3c6ef372fe94f82b ^ 0xa5a5a5a5a5a5a5a5
	init3      = 0xa54ff53a5f1d36f1 ^ 0xa5a5a5a5a5a5a5a5
	init4      = 0x510e527fade682d1 ^ 0xa5a5a5a5a5a5a5a5
	init5      = 0x9b05688c2b3e6c1f ^ 0xa5a5a5a5a5a5a5a5
	init6      = 0x1f83d9abfb41bd6b ^ 0xa5a5a5a5a5a5a5a5
	init7      = 0x5be0cd19137e2179 ^ 0xa5a5a5a5a5a5a5a5
	sha512size = 64
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	h   [8]uint64
	x   [chunk]byte
	nx  int
	len uint64
	t   int
}

func (d *digest) Reset() {

	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7

	d.Write([]byte("SHA-512/"))
	d.Write([]byte(strconv.Itoa(d.t)))
	d.writePad()

	d.nx = 0
	d.len = 0
}

// New returns a new hash.Hash computing the SHA512/t checksum.
func New(t int) hash.Hash {
	d := new(digest)

	if t >= 512 || t < 0 {
		panic("sha512t: t out of range")
	}

	if t%8 != 0 {
		panic("sha512t: t not a multiple of 8")
	}

	if t == 384 {
		panic("sha512t: use sha384 for t=384")
	}

	d.t = t
	d.Reset()

	return d
}

func (d *digest) Size() int {
	return d.t / 8
}

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := len(p)
		if n > chunk-d.nx {
			n = chunk - d.nx
		}
		for i := 0; i < n; i++ {
			d.x[d.nx+i] = p[i]
		}
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[0:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *digest) Sum(in []byte) []byte {
	// Make a copy of d0 so that caller can keep writing and summing.
	d := new(digest)
	*d = *d0

	d.writePad()

	size := d.t / 8
	digest := make([]byte, sha512size)

	for i, s := range d.h {
		digest[i*8] = byte(s >> 56)
		digest[i*8+1] = byte(s >> 48)
		digest[i*8+2] = byte(s >> 40)
		digest[i*8+3] = byte(s >> 32)
		digest[i*8+4] = byte(s >> 24)
		digest[i*8+5] = byte(s >> 16)
		digest[i*8+6] = byte(s >> 8)
		digest[i*8+7] = byte(s)
	}

	return append(in, digest[:size]...)
}

func (d *digest) writePad() {
	// Padding.  Add a 1 bit and 0 bits until 112 bytes mod 128.
	len := d.len
	var tmp [128]byte
	tmp[0] = 0x80
	if len%128 < 112 {
		d.Write(tmp[0 : 112-len%128])
	} else {
		d.Write(tmp[0 : 128+112-len%128])
	}

	// Length in bits.
	len <<= 3
	for i := uint(0); i < 16; i++ {
		tmp[i] = byte(len >> (120 - 8*i))
	}
	d.Write(tmp[0:16])

	if d.nx != 0 {
		panic("d.nx != 0")
	}
}
