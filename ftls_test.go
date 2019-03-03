package mint

import (
	"fmt"
	"github.com/bifurcation/mint/syntax"
	"testing"
)

func newInstance(t *testing.T) (*fClient, *fServer) {
	group := X25519
	scheme := Ed25519
	params := cipherSuiteMap[TLS_AES_128_GCM_SHA256]
	clientKeyID := []byte("client")
	serverKeyID := []byte("server")

	clientPriv, err := newSigningKey(scheme)
	assertNotError(t, err, "Failed to generate client signing key")

	serverPriv, err := newSigningKey(scheme)
	assertNotError(t, err, "Failed to generate server signing key")

	client := &fClient{
		fConfig: fConfig{
			group:     group,
			scheme:    scheme,
			params:    params,
			myPriv:    clientPriv,
			peerPub:   serverPriv.Public(),
			myKeyID:   clientKeyID,
			peerKeyID: serverKeyID,
		},
	}

	server := &fServer{
		fConfig: fConfig{
			group:     group,
			scheme:    scheme,
			params:    params,
			myPriv:    serverPriv,
			peerPub:   clientPriv.Public(),
			myKeyID:   serverKeyID,
			peerKeyID: clientKeyID,
		},
	}

	return client, server
}

func TestFTLS(t *testing.T) {
	client, server := newInstance(t)

	m1, err := client.NewMessage1()
	assertNotError(t, err, "Failed to generate Message1")

	m2, err := server.HandleMessage1(m1)
	assertNotError(t, err, "Failed to handle Message1")

	m3, err := client.HandleMessage2(m2)
	assertNotError(t, err, "Failed to handle Message2")

	err = server.HandleMessage3(m3)
	assertNotError(t, err, "Failed to handle Message3")

	assertByteEquals(t, client.clientAppSecret, server.clientAppSecret)
	assertByteEquals(t, client.serverAppSecret, server.serverAppSecret)

	/////

	m1data, err := syntax.Marshal(m1)
	assertNotError(t, err, "Failed to marshal Message1")

	m2data, err := syntax.Marshal(m2)
	assertNotError(t, err, "Failed to marshal Message2")

	m3data, err := syntax.Marshal(m3)
	assertNotError(t, err, "Failed to marshal Message3")

	fmt.Printf("m1: %3d\n", len(m1data))
	fmt.Printf("m2: %3d\n", len(m2data))
	fmt.Printf("m3: %3d\n", len(m3data))
}
