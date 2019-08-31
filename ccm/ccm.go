package ccm

import (
	"bytes"
	"crypto/cipher"
	"errors"
)

// Cf. https://gist.github.com/hirochachacha/abb76ff71573dea2ef42

type mac struct {
	ci []byte
	p  int
	c  cipher.Block
}

func newMAC(c cipher.Block) *mac {
	return &mac{
		c:  c,
		ci: make([]byte, c.BlockSize()),
	}
}

func (m *mac) Reset() {
	for i := range m.ci {
		m.ci[i] = 0
	}
	m.p = 0
}

func (m *mac) Write(p []byte) (n int, err error) {
	for _, c := range p {
		if m.p >= len(m.ci) {
			m.c.Encrypt(m.ci, m.ci)
			m.p = 0
		}
		m.ci[m.p] ^= c
		m.p++
	}
	return len(p), nil
}

// PadZero emulates zero byte padding.
func (m *mac) PadZero() {
	if m.p != 0 {
		m.c.Encrypt(m.ci, m.ci)
		m.p = 0
	}
}

func (m *mac) Sum(in []byte) []byte {
	if m.p != 0 {
		m.c.Encrypt(m.ci, m.ci)
		m.p = 0
	}
	return append(in, m.ci...)
}

func (m *mac) Size() int { return len(m.ci) }

func (m *mac) BlockSize() int { return 16 }

type ccm struct {
	c                cipher.Block
	mac              *mac
	nonceSize        int
	tagSize          int
	maxPlaintextSize uint64
}

func NewCCMWithNonceAndTagSizes(c cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if c.BlockSize() != 16 {
		return nil, errors.New("cipher: CCM mode requires 128-bit block cipher")
	}

	if !(7 <= nonceSize && nonceSize <= 13) {
		return nil, errors.New("cipher: invalid nonce size")
	}

	if !(4 <= tagSize && tagSize <= 16 && tagSize&1 == 0) {
		return nil, errors.New("cipher: invalid tag size")
	}

	return &ccm{
		c:                c,
		mac:              newMAC(c),
		nonceSize:        nonceSize,
		tagSize:          tagSize,
		maxPlaintextSize: maxUvarint(15 - nonceSize),
	}, nil
}

func (ccm *ccm) NonceSize() int {
	return ccm.nonceSize
}

func (ccm *ccm) Overhead() int {
	return ccm.tagSize
}

func (ccm *ccm) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != ccm.nonceSize {
		panic("cipher: incorrect nonce length given to CCM")
	}

	// AEAD interface doesn't provide a way to return errors.
	// So it returns nil instead.
	if ccm.maxPlaintextSize < uint64(len(plaintext)) {
		return nil
	}

	ret, ciphertext := sliceForAppend(dst, len(plaintext)+ccm.mac.Size())

	// Formatting of the Counter Blocks are defined in A.3.
	Ctr := make([]byte, 16)               // Ctr0
	Ctr[0] = byte(15 - ccm.nonceSize - 1) // [q-1]3
	copy(Ctr[1:], nonce)                  // N

	S0 := ciphertext[len(plaintext):] // S0
	ccm.c.Encrypt(S0, Ctr)

	Ctr[15] = 1 // Ctr1

	ctr := cipher.NewCTR(ccm.c, Ctr)

	ctr.XORKeyStream(ciphertext, plaintext)

	T := ccm.getTag(Ctr, data, plaintext)

	xorBytes(S0, S0, T) // T^S0

	return ret[:len(plaintext)+ccm.tagSize]
}

func (ccm *ccm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != ccm.nonceSize {
		panic("cipher: incorrect nonce length given to CCM")
	}

	if len(ciphertext) < ccm.tagSize {
		panic("cipher: incorrect ciphertext length given to CCM")
	}

	if maxUvarint(15-ccm.nonceSize) < uint64(len(ciphertext)-ccm.tagSize) {
		return nil, errors.New("cipher: len(ciphertext)-tagSize exceeds the maximum payload size")
	}

	ret, plaintext := sliceForAppend(dst, len(ciphertext)-ccm.tagSize)

	// Formatting of the Counter Blocks are defined in A.3.
	Ctr := make([]byte, 16)               // Ctr0
	Ctr[0] = byte(15 - ccm.nonceSize - 1) // [q-1]3
	copy(Ctr[1:], nonce)                  // N

	S0 := make([]byte, 16) // S0
	ccm.c.Encrypt(S0, Ctr)

	Ctr[15] = 1 // Ctr1

	ctr := cipher.NewCTR(ccm.c, Ctr)

	ctr.XORKeyStream(plaintext, ciphertext[:len(plaintext)])

	T := ccm.getTag(Ctr, data, plaintext)

	xorBytes(T, T, S0)

	if !bytes.Equal(T[:ccm.tagSize], ciphertext[len(plaintext):]) {
		return nil, errors.New("cipher: message authentication failed")
	}

	return ret, nil
}

// getTag reuses a Ctr block for making the B0 block because of some parts are the same.
// For more details, see A.2 and A.3.
func (ccm *ccm) getTag(Ctr, data, plaintext []byte) []byte {
	ccm.mac.Reset()

	B := Ctr                                                // B0
	B[0] |= byte(((ccm.tagSize - 2) / 2) << 3)              // [(t-2)/2]3
	putUvarint(B[1+ccm.nonceSize:], uint64(len(plaintext))) // Q

	if len(data) > 0 {
		B[0] |= 1 << 6 // Adata

		ccm.mac.Write(B)

		if len(data) < (1<<15 - 1<<7) {
			putUvarint(B[:2], uint64(len(data)))

			ccm.mac.Write(B[:2])
		} else if len(data) <= 1<<31-1 {
			B[0] = 0xff
			B[1] = 0xfe
			putUvarint(B[2:6], uint64(len(data)))

			ccm.mac.Write(B[:6])
		} else {
			B[0] = 0xff
			B[1] = 0xff
			putUvarint(B[2:10], uint64(len(data)))

			ccm.mac.Write(B[:10])
		}
		ccm.mac.Write(data)
		ccm.mac.PadZero()
	} else {
		ccm.mac.Write(B)
	}

	ccm.mac.Write(plaintext)
	ccm.mac.PadZero()

	return ccm.mac.Sum(nil)
}

func maxUvarint(n int) uint64 {
	return 1<<uint(n*8) - 1
}

// put uint64 as big endian.
func putUvarint(bs []byte, u uint64) {
	for i := 0; i < len(bs); i++ {
		bs[i] = byte(u >> uint(8*(len(bs)-1-i)))
	}
}

// defined in crypto/cipher/gcm.go
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// defined in crypto/cipher/xor.go
func xorBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}
