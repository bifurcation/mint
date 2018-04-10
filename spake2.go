package mint

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
)

const (
	M256hex = "04" +
		"886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f" +
		"5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20"
	N256hex = "04" +
		"d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49" +
		"07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7"
	M384hex = "04" +
		"0ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853" +
		"97592c55797cdd77c0715cb7df2150220a0119866486af4234f390aad1f6addde5930909adc67a1fc0c99ba3d52dc5dd"
	N384hex = "04" +
		"c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10" +
		"c38b7d7f4e7f320317cd717315a797c7e02933aef68b364cbf84ebc619bedbe21ff5c69ea0f1fed5d7e3200418073f40"
	M521hex = "04" +
		"003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608c" +
		"fae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa" +
		"01bdd179a3d547610892e9b96dea1eab10bdd7ac5ae0cf75aa0f853bfd185cf782" +
		"f894301998b11d1898ede2701dca37a2bb50b4f519c3d89a7d054b51fb84912192"
	N521hex = "04" +
		"00c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b25" +
		"32d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25" +
		"01c62bee650c9287a651bb75c7f39a2006873347b769840d261d17760b107e29f0" +
		"91d556a82a2e4cde0c40b84b95b878db2489ef760206424b3fe7968aa8e0b1f334"
)

var (
	M256x, M256y *big.Int
	N256x, N256y *big.Int
	M384x, M384y *big.Int
	N384x, N384y *big.Int
	M521x, M521y *big.Int
	N521x, N521y *big.Int
)

func init() {
	p256 := elliptic.P256()
	p384 := elliptic.P384()
	p521 := elliptic.P521()

	M256, _ := hex.DecodeString(M256hex)
	N256, _ := hex.DecodeString(N256hex)
	M384, _ := hex.DecodeString(M384hex)
	N384, _ := hex.DecodeString(N384hex)
	M521, _ := hex.DecodeString(M521hex)
	N521, _ := hex.DecodeString(N521hex)

	M256x, M256y = elliptic.Unmarshal(p256, M256)
	N256x, N256y = elliptic.Unmarshal(p256, N256)
	M384x, M384y = elliptic.Unmarshal(p384, M384)
	N384x, N384y = elliptic.Unmarshal(p384, N384)
	M521x, M521y = elliptic.Unmarshal(p521, M521)
	N521x, N521y = elliptic.Unmarshal(p521, N521)
}

func spakeBasePoint(group NamedGroup, client bool) (x, y *big.Int) {
	switch group {
	case P256:
		if client {
			return M256x, M256y
		} else {
			return N256x, N256y
		}
	case P384:
		if client {
			return M384x, M384y
		} else {
			return N384x, N384y
		}
	case P521:
		if client {
			return M521x, M521y
		} else {
			return N521x, N521y
		}
	default:
		panic("This should be pre-filtered by SPAKE functions")
	}
}

// Generate an ephemeral `x` and return `w * M + x * G` (or the
// appropriate server-side equivalents)
func newSPAKE2KeyShare(group NamedGroup, client bool, w []byte) (x, T []byte, err error) {
	switch group {
	case P256, P384, P521:
		crv := curveFromNamedGroup(group)
		Mx, My := spakeBasePoint(group, client)

		wMx, wMy := crv.Params().ScalarMult(Mx, My, w)

		var xGx, xGy *big.Int
		x, xGx, xGy, err = elliptic.GenerateKey(crv, prng)
		if err != nil {
			return
		}

		Tx, Ty := crv.Params().Add(wMx, wMy, xGx, xGy)
		T = elliptic.Marshal(crv, Tx, Ty)

		return x, T, nil

	default:
		return nil, nil, fmt.Errorf("tls.newspake2: Unsupported group %v", group)
	}
}

// C->S: T = w*M + x*G
// S->C: S = w*N + y*G
//
// K = x * (S - w*N) = y * (T - w*M)

// Generate an ephemeral `x` and return `K = x * (S - w*N)` (or the
// appropriate server-side equivalents)
func spake2KeyAgreement(group NamedGroup, client bool, S, x, w []byte) ([]byte, error) {
	switch group {
	case P256, P384, P521:
		crv := curveFromNamedGroup(group)
		Sx, Sy := elliptic.Unmarshal(crv, S)
		Nx, Ny := spakeBasePoint(group, !client)

		wNx, wNy := crv.Params().ScalarMult(Nx, Ny, w)
		wNy.Neg(wNy)
		wNy.Mod(wNy, crv.Params().P)

		SwNx, SwNy := crv.Params().Add(Sx, Sy, wNx, wNy)
		Kx, _ := crv.Params().ScalarMult(SwNx, SwNy, x)

		xBytes := Kx.Bytes()
		numBytes := len(crv.Params().P.Bytes())
		ret := make([]byte, numBytes)
		copy(ret[numBytes-len(xBytes):], xBytes)
		return ret, nil

	default:
		return nil, fmt.Errorf("tls.spake2: Unsupported group %v", group)
	}
}
