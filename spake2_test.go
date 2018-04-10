package mint

import (
	"testing"
)

func TestSPAKE2(t *testing.T) {
	groups := []NamedGroup{P256, P384, P521}
	w := []byte{0, 1, 2, 3, 4, 5, 6, 7}

	for _, group := range groups {
		x, T, err := newSPAKE2KeyShare(group, true, w)
		assertNotError(t, err, "Failed to generate client key share")

		y, S, err := newSPAKE2KeyShare(group, false, w)
		assertNotError(t, err, "Failed to generate server key share")

		Kc, err := spake2KeyAgreement(group, true, S, x, w)
		assertNotError(t, err, "Failed to generate client key")

		Ks, err := spake2KeyAgreement(group, false, T, y, w)
		assertNotError(t, err, "Failed to generate server key")

		assertByteEquals(t, Ks, Kc)
	}
}
