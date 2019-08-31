package ccm

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

func unhex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func TestCCM(t *testing.T) {
	C4A := make([]byte, 524288/8)
	for i := range C4A {
		C4A[i] = byte(i)
	}

	cases := []struct {
		Key        []byte
		Nonce      []byte
		Data       []byte
		PlainText  []byte
		CipherText []byte
		TagLen     int
	}{
		{ // C.1
			unhex("404142434445464748494a4b4c4d4e4f"),
			unhex("10111213141516"),
			unhex("0001020304050607"),
			unhex("20212223"),
			unhex("7162015b4dac255d"),
			4,
		},
		{ // C.2
			unhex("404142434445464748494a4b4c4d4e4f"),
			unhex("1011121314151617"),
			unhex("000102030405060708090a0b0c0d0e0f"),
			unhex("202122232425262728292a2b2c2d2e2f"),
			unhex("d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd"),
			6,
		},
		{ // C.3
			unhex("404142434445464748494a4b4c4d4e4f"),
			unhex("101112131415161718191a1b"),
			unhex("000102030405060708090a0b0c0d0e0f10111213"),
			unhex("202122232425262728292a2b2c2d2e2f3031323334353637"),
			unhex("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951"),
			8,
		},
		{ // C.4
			unhex("404142434445464748494a4b4c4d4e4f"),
			unhex("101112131415161718191a1b1c"),
			C4A,
			unhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
			unhex("69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b"),
			14,
		},
	}

	for i, c := range cases {
		block, err := aes.NewCipher(c.Key)
		if err != nil {
			t.Fatalf("Error creating cipher: %v", err)
		}

		ccm, err := NewCCMWithNonceAndTagSizes(block, len(c.Nonce), c.TagLen)
		if err != nil {
			t.Fatalf("[%d] Error creating CCM: %v", i, err)
		}

		ct := ccm.Seal(nil, c.Nonce, c.PlainText, c.Data)

		if !bytes.Equal(c.CipherText, ct) {
			t.Fatalf("[%d] Incorrect ciphertext: [%x] [%x]", i, c.CipherText, ct)
		}

		pt, err := ccm.Open(nil, c.Nonce, c.CipherText, c.Data)
		if err != nil {
			t.Fatalf("[%d] Authenticaiton failure: [%v]", i, err)
		}

		if !bytes.Equal(c.PlainText, pt) {
			t.Fatalf("[%d] Incorrect ciphertext: [%x] [%x]", i, c.PlainText, pt)
		}
	}
}
