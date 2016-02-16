package mint

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

var prng = rand.Reader

func curveFromNamedGroup(group namedGroup) (crv elliptic.Curve) {
	switch group {
	case namedGroupP256:
		crv = elliptic.P256()
	case namedGroupP384:
		crv = elliptic.P384()
	case namedGroupP521:
		crv = elliptic.P521()
	}
	return
}

func newKeyShare(group namedGroup) (pub []byte, priv []byte, err error) {
	switch group {
	case namedGroupP256, namedGroupP384, namedGroupP521:
		var x, y *big.Int
		crv := curveFromNamedGroup(group)
		priv, x, y, err = elliptic.GenerateKey(crv, prng)
		if err != nil {
			return
		}

		pub = elliptic.Marshal(crv, x, y)
		return

	default:
		return nil, nil, fmt.Errorf("tls.newkeyshare: Unsupported group %v", group)
	}
}

func keyAgreement(group namedGroup, pub []byte, priv []byte) ([]byte, error) {
	switch group {
	case namedGroupP256, namedGroupP384, namedGroupP521:
		crv := curveFromNamedGroup(group)
		pubX, pubY := elliptic.Unmarshal(crv, pub)
		x, _ := crv.Params().ScalarMult(pubX, pubY, priv)

		curveSize := len(crv.Params().P.Bytes())
		xBytes := x.Bytes()
		if len(xBytes) < curveSize {
			xBytes = append(bytes.Repeat([]byte{0}, curveSize-len(xBytes)), xBytes...)
		}
		return xBytes, nil

	default:
		return nil, fmt.Errorf("tls.keyagreement: Unsupported group %v", group)
	}
}
