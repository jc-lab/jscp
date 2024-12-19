package session

import (
	"bytes"
	"crypto/ecdh"
	srand "crypto/rand"
	"encoding/hex"
	"github.com/jc-lab/jscp/go/cryptoutil"
	"github.com/jc-lab/jscp/go/payloadpb"
	"github.com/jc-lab/jscp/go/sessionstate"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
	"math/rand/v2"
	"testing"
	"time"
)

var ed25519Algorithm = &cryptoutil.Ed25519Algorithm{}
var x25519Algorithm = &cryptoutil.X25519Algorithm{}
var p256DhAlgorithm = &p256DhAlgorithmImpl{}

type p256DhAlgorithmImpl struct{}

func (p *p256DhAlgorithmImpl) GetType() payloadpb.DHAlgorithm {
	return payloadpb.DHAlgorithm_DHECC
}

func (p *p256DhAlgorithmImpl) Generate() (*cryptoutil.DHKeyPair, error) {
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(srand.Reader)
	if err != nil {
		return nil, err
	}
	eccPrivateKey := cryptoutil.NewECCPrivateKey(nil, privateKey, cryptoutil.KeyUsageDH)

	return &cryptoutil.DHKeyPair{
		Private: eccPrivateKey,
		Public:  eccPrivateKey.GetDHPublic(),
	}, nil
}

func (p *p256DhAlgorithmImpl) UnmarshalDHPublicKey(input []byte) (cryptoutil.DHPublicKey, error) {
	//TODO implement me
	panic("implement me")
}

var testCases = []struct {
	name                 string
	serverAdditional     []byte
	clientAdditional     []byte
	expectAdditional     bool
	serverUseSignature   bool
	clientUseSignature   bool
	serverUseDHSignature string
	clientUseDHSignature string
}{
	{
		name:             "no_static-no_static-wo_additional",
		serverAdditional: nil,
		clientAdditional: nil,
		expectAdditional: false,
	},
	{
		name:             "no_static-no_static-with_additional",
		serverAdditional: []byte("i am server"),
		clientAdditional: []byte("i am client"),
		expectAdditional: true,
	},

	{
		name:               "static(signature)-static(signature)-wo_additional",
		serverAdditional:   nil,
		clientAdditional:   nil,
		expectAdditional:   false,
		serverUseSignature: true,
		clientUseSignature: true,
	},
	{
		name:               "static(signature)-static(signature)-with_additional",
		serverAdditional:   []byte("i am server"),
		clientAdditional:   []byte("i am client"),
		expectAdditional:   true,
		serverUseSignature: true,
		clientUseSignature: true,
	},

	{
		name:                 "static(x25519)-static(x25519)-wo_additional",
		serverAdditional:     nil,
		clientAdditional:     nil,
		expectAdditional:     false,
		serverUseSignature:   true,
		clientUseSignature:   true,
		serverUseDHSignature: "x25519",
		clientUseDHSignature: "x25519",
	},
	{
		name:                 "static(x25519)-static(x25519)-with_additional",
		serverAdditional:     []byte("i am server"),
		clientAdditional:     []byte("i am client"),
		expectAdditional:     true,
		serverUseSignature:   true,
		clientUseSignature:   true,
		serverUseDHSignature: "x25519",
		clientUseDHSignature: "x25519",
	},

	{
		name:                 "static(p256)-static(p256)-wo_additional",
		serverAdditional:     nil,
		clientAdditional:     nil,
		expectAdditional:     false,
		serverUseSignature:   true,
		clientUseSignature:   true,
		serverUseDHSignature: "p256",
		clientUseDHSignature: "p256",
	},
	{
		name:                 "static(p256)-static(p256)-with_additional",
		serverAdditional:     []byte("i am server"),
		clientAdditional:     []byte("i am client"),
		expectAdditional:     true,
		serverUseSignature:   true,
		clientUseSignature:   true,
		serverUseDHSignature: "p256",
		clientUseDHSignature: "p256",
	},
	{
		name:                 "no_static(p256)-static(p256)-with_additional",
		serverAdditional:     []byte("i am server"),
		clientAdditional:     []byte("i am client"),
		expectAdditional:     true,
		serverUseSignature:   false,
		clientUseSignature:   true,
		serverUseDHSignature: "",
		clientUseDHSignature: "p256",
	},
	{
		name:                 "static(p256)-no_static(p256)-with_additional",
		serverAdditional:     []byte("i am server"),
		clientAdditional:     []byte("i am client"),
		expectAdditional:     true,
		serverUseSignature:   true,
		clientUseSignature:   false,
		serverUseDHSignature: "p256",
		clientUseDHSignature: "",
	},

	{
		name:                 "data communication",
		serverAdditional:     []byte("i am server"),
		clientAdditional:     []byte("i am client"),
		expectAdditional:     true,
		serverUseSignature:   true,
		clientUseSignature:   true,
		serverUseDHSignature: "p256",
		clientUseDHSignature: "p256",
	},
}

func TestCommunicationDynamic(t *testing.T) {
	var seed [32]byte
	srand.Reader.Read(seed[:])
	randReader := rand.NewChaCha8(seed)
	buf := make([]byte, 65536)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var serverPrivateKey cryptoutil.PrivateKey
			var clientPrivateKey cryptoutil.PrivateKey

			if tc.serverUseSignature {
				if tc.serverUseDHSignature != "" {
					var algo cryptoutil.DHAlgorithm
					switch tc.serverUseDHSignature {
					case "x25519":
						algo = x25519Algorithm
					case "p256":
						algo = p256DhAlgorithm
					}
					if keyPair, err := algo.Generate(); err != nil {
						t.Fatal(err)
					} else {
						serverPrivateKey = keyPair.Private
					}
				} else {
					var err error
					if serverPrivateKey, err = ed25519Algorithm.Generate(); err != nil {
						t.Fatal(err)
					}
				}
			}

			if tc.clientUseSignature {
				if tc.clientUseDHSignature != "" {
					var algo cryptoutil.DHAlgorithm
					switch tc.clientUseDHSignature {
					case "x25519":
						algo = x25519Algorithm
					case "p256":
						algo = p256DhAlgorithm
					}
					if keyPair, err := algo.Generate(); err != nil {
						t.Fatal(err)
					} else {
						clientPrivateKey = keyPair.Private
					}
				} else {
					var err error
					if clientPrivateKey, err = ed25519Algorithm.Generate(); err != nil {
						t.Fatal(err)
					}
				}
			}

			// Create channels for communication between client and server
			clientToServer := make(chan *payloadpb.Payload, 1)
			serverToClient := make(chan *payloadpb.Payload, 1)

			// Create server and client with their respective send functions
			server, err := NewSession(false, func(payload *payloadpb.Payload) {
				serverToClient <- payload
			}, serverPrivateKey)
			if err != nil {
				t.Fatal(err)
			}

			client, err := NewSession(true, func(payload *payloadpb.Payload) {
				clientToServer <- payload
			}, clientPrivateKey)
			if err != nil {
				t.Fatal(err)
			}

			client.symmetricStateFactory = func() sessionstate.SymmetricState {
				return &testSymmetricState{}
			}
			server.symmetricStateFactory = client.symmetricStateFactory
			client.localState = &testSymmetricState{}
			client.remoteState = &testSymmetricState{}
			server.localState = &testSymmetricState{}
			server.remoteState = &testSymmetricState{}

			// Start goroutines to handle message passing
			go func() {
				for payload := range serverToClient {
					err := client.HandleReceive(payload)
					if err != nil {
						t.Fatalf("client.HandleReceive error: %v", err)
					}
				}
			}()

			go func() {
				for payload := range clientToServer {
					err := server.HandleReceive(payload)
					if err != nil {
						t.Fatalf("server.HandleReceive error: %v", err)
					}
				}
			}()

			// Start handshakes
			clientHandshakeCh, err := client.Handshake(tc.clientAdditional)
			if err != nil {
				t.Fatalf("client.Handshake error: %v", err)
			}

			serverHandshakeCh, err := server.Handshake(tc.serverAdditional)
			if err != nil {
				t.Fatalf("server.Handshake error: %v", err)
			}

			// Wait for both handshakes to complete with timeout
			timer := time.NewTimer(500 * time.Millisecond)
			defer timer.Stop()

			var clientResult, serverResult *HandshakeResult

			// Wait for client result
			select {
			case result := <-clientHandshakeCh:
				if result.Error != nil {
					t.Fatalf("client handshake failed: %v", result.Error)
				}
				clientResult = result
			case <-timer.C:
				t.Fatal("timeout waiting for client handshake")
			}

			// Wait for server result
			select {
			case result := <-serverHandshakeCh:
				if result.Error != nil {
					t.Fatalf("server handshake failed: %v", result.Error)
				}
				serverResult = result
			case <-timer.C:
				t.Fatal("timeout waiting for server handshake")
			}

			// Verify additional data if expected
			if tc.expectAdditional {
				if clientResult.PeerAdditionalData == nil {
					t.Error("client result: expected peer additional data, got nil")
				} else if !bytes.Equal(clientResult.PeerAdditionalData, tc.serverAdditional) {
					t.Errorf("client result: peer additional data mismatch\nexpected: %v\ngot: %v",
						tc.serverAdditional, clientResult.PeerAdditionalData)
				}

				if serverResult.PeerAdditionalData == nil {
					t.Error("server result: expected peer additional data, got nil")
				} else if !bytes.Equal(serverResult.PeerAdditionalData, tc.clientAdditional) {
					t.Errorf("server result: peer additional data mismatch\nexpected: %v\ngot: %v",
						tc.clientAdditional, serverResult.PeerAdditionalData)
				}
			} else {
				if clientResult.PeerAdditionalData != nil {
					t.Error("client result: expected nil peer additional data")
				}
				if serverResult.PeerAdditionalData != nil {
					t.Error("server result: expected nil peer additional data")
				}
			}

			if tc.serverUseSignature {
				compareSignaturePublicKey(t, serverPrivateKey.GetPublic(), clientResult.RemotePublicKey)
			}
			if tc.clientUseSignature {
				compareSignaturePublicKey(t, clientPrivateKey.GetPublic(), serverResult.RemotePublicKey)
			}

			clientStateA := client.localState.(*testSymmetricState)
			clientStateB := server.remoteState.(*testSymmetricState)
			assert.Equal(t, clientStateA.recordedKeys, clientStateB.recordedKeys)

			serverStateA := client.remoteState.(*testSymmetricState)
			serverStateB := server.localState.(*testSymmetricState)
			assert.Equal(t, serverStateA.recordedKeys, serverStateB.recordedKeys)

			assert.Equal(t, clientStateA.recordedKeys, serverStateB.recordedKeys)

			index := 0

			if tc.serverUseDHSignature != "" {
				out, _ := client.ephemeralKeyPair.Private.DH(server.staticKeyPair.GetPublic().(cryptoutil.DHPublicKey))
				assert.Equal(t, out, clientStateA.recordedKeys[index])
				index++
			}
			if tc.clientUseDHSignature != "" {
				out, _ := client.staticKeyPair.(cryptoutil.DHPrivateKey).DH(server.ephemeralKeyPair.Public)
				assert.Equal(t, out, clientStateA.recordedKeys[index])
				index++
			}
			if true {
				out, _ := client.ephemeralKeyPair.Private.DH(server.ephemeralKeyPair.Public)
				assert.Equal(t, out, clientStateA.recordedKeys[index])
				index++
			}
			assert.Equal(t, len(clientStateA.recordedKeys), index)

			for i := 0; i < 100; i++ {
				randReader.Read(buf)
				server.Write(buf)
				recv, err := client.Read()
				assert.NoError(t, err)
				assert.Equal(t, buf, recv)

				randReader.Read(buf)
				client.Write(buf)
				recv, err = server.Read()
				assert.NoError(t, err)
				assert.Equal(t, buf, recv)
			}

			// Close channels
			close(clientToServer)
			close(serverToClient)
		})
	}
}

func TestCommunicationDeterministic(t *testing.T) {
	for _, tc := range testCases {
		if tc.clientUseDHSignature == "p256" || tc.serverUseDHSignature == "p256" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			var serverPrivateKey cryptoutil.PrivateKey
			var clientPrivateKey cryptoutil.PrivateKey

			if tc.serverUseSignature {
				if tc.serverUseDHSignature != "" {
					serverPrivateKey = decodeX25519Key(t, "27c0beabad79e248d280c2cb48f4704d61904a8447e1b5fb95e914432e772d6d")
				} else {
					serverPrivateKey = decodeEd25519Key(t, "adde2498a77bcded1a89416093bf071fd5f5d89e6caa2e8c4baff1b837bb6e1897d93a4c69d3ab58ff63c341e5564d07cbf9f4330f64ad87ab37c48ce4c7732d")
				}
			}

			if tc.clientUseSignature {
				if tc.clientUseDHSignature != "" {
					clientPrivateKey = decodeX25519Key(t, "2e93f3dc9eef2ee59282b13aa90a8aba079cf5d584959795d72c2bfd8c9d9555")
				} else {
					clientPrivateKey = decodeEd25519Key(t, "6f3ae78202e786109b77afeb6a8ebcd7dbbf31b534f755582ea3703a604610c82c0c79fb73469f3b71badb9a6d995ab2dcbb991db2305e72906ac2640255d03a")
				}
			}

			// Create channels for communication between client and server
			clientToServer := make(chan *payloadpb.Payload, 1)
			serverToClient := make(chan *payloadpb.Payload, 1)

			// Create server and client with their respective send functions
			server, err := NewSession(false, func(payload *payloadpb.Payload) {
				serverToClient <- payload
			}, serverPrivateKey)
			if err != nil {
				t.Fatal(err)
			}

			client, err := NewSession(true, func(payload *payloadpb.Payload) {
				clientToServer <- payload
			}, clientPrivateKey)
			if err != nil {
				t.Fatal(err)
			}

			client.symmetricStateFactory = func() sessionstate.SymmetricState {
				return &testSymmetricState{}
			}
			server.symmetricStateFactory = client.symmetricStateFactory
			client.localState = &testSymmetricState{}
			client.remoteState = &testSymmetricState{}
			server.localState = &testSymmetricState{}
			server.remoteState = &testSymmetricState{}

			// Start goroutines to handle message passing
			go func() {
				for payload := range serverToClient {
					err := client.HandleReceive(payload)
					if err != nil {
						t.Fatalf("client.HandleReceive error: %v", err)
					}
				}
			}()

			go func() {
				for payload := range clientToServer {
					err := server.HandleReceive(payload)
					if err != nil {
						t.Fatalf("server.HandleReceive error: %v", err)
					}
				}
			}()

			// Start handshakes
			clientHandshakeCh, err := client.Handshake(tc.clientAdditional)
			if err != nil {
				t.Fatalf("client.Handshake error: %v", err)
			}

			serverHandshakeCh, err := server.Handshake(tc.serverAdditional)
			if err != nil {
				t.Fatalf("server.Handshake error: %v", err)
			}

			// Wait for both handshakes to complete with timeout
			timer := time.NewTimer(500 * time.Millisecond)
			defer timer.Stop()

			var clientResult, serverResult *HandshakeResult

			// Wait for client result
			select {
			case result := <-clientHandshakeCh:
				if result.Error != nil {
					t.Fatalf("client handshake failed: %v", result.Error)
				}
				clientResult = result
			case <-timer.C:
				t.Fatal("timeout waiting for client handshake")
			}

			// Wait for server result
			select {
			case result := <-serverHandshakeCh:
				if result.Error != nil {
					t.Fatalf("server handshake failed: %v", result.Error)
				}
				serverResult = result
			case <-timer.C:
				t.Fatal("timeout waiting for server handshake")
			}

			// Verify additional data if expected
			if tc.expectAdditional {
				if clientResult.PeerAdditionalData == nil {
					t.Error("client result: expected peer additional data, got nil")
				} else if !bytes.Equal(clientResult.PeerAdditionalData, tc.serverAdditional) {
					t.Errorf("client result: peer additional data mismatch\nexpected: %v\ngot: %v",
						tc.serverAdditional, clientResult.PeerAdditionalData)
				}

				if serverResult.PeerAdditionalData == nil {
					t.Error("server result: expected peer additional data, got nil")
				} else if !bytes.Equal(serverResult.PeerAdditionalData, tc.clientAdditional) {
					t.Errorf("server result: peer additional data mismatch\nexpected: %v\ngot: %v",
						tc.clientAdditional, serverResult.PeerAdditionalData)
				}
			} else {
				if clientResult.PeerAdditionalData != nil {
					t.Error("client result: expected nil peer additional data")
				}
				if serverResult.PeerAdditionalData != nil {
					t.Error("server result: expected nil peer additional data")
				}
			}

			if tc.serverUseSignature {
				compareSignaturePublicKey(t, serverPrivateKey.GetPublic(), clientResult.RemotePublicKey)
			}
			if tc.clientUseSignature {
				compareSignaturePublicKey(t, clientPrivateKey.GetPublic(), serverResult.RemotePublicKey)
			}

			clientStateA := client.localState.(*testSymmetricState)
			clientStateB := server.remoteState.(*testSymmetricState)
			assert.Equal(t, clientStateA.recordedKeys, clientStateB.recordedKeys)

			serverStateA := client.remoteState.(*testSymmetricState)
			serverStateB := server.localState.(*testSymmetricState)
			assert.Equal(t, serverStateA.recordedKeys, serverStateB.recordedKeys)

			assert.Equal(t, clientStateA.recordedKeys, serverStateB.recordedKeys)

			index := 0

			if tc.serverUseDHSignature != "" {
				out, _ := client.ephemeralKeyPair.Private.DH(server.staticKeyPair.GetPublic().(cryptoutil.DHPublicKey))
				assert.Equal(t, out, clientStateA.recordedKeys[index])
				index++
			}
			if tc.clientUseDHSignature != "" {
				out, _ := client.staticKeyPair.(cryptoutil.DHPrivateKey).DH(server.ephemeralKeyPair.Public)
				assert.Equal(t, out, clientStateA.recordedKeys[index])
				index++
			}
			if true {
				out, _ := client.ephemeralKeyPair.Private.DH(server.ephemeralKeyPair.Public)
				assert.Equal(t, out, clientStateA.recordedKeys[index])
				index++
			}
			assert.Equal(t, len(clientStateA.recordedKeys), index)

			// Close channels
			close(clientToServer)
			close(serverToClient)
		})
	}
}

func compareSignaturePublicKey(t *testing.T, expected cryptoutil.PublicKey, actual cryptoutil.PublicKey) {
	aProto, err := expected.MarshalToProto()
	if err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, actual)
	if actual == nil {
		return
	}
	bProto, err := actual.MarshalToProto()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, aProto, bProto)
}

type testSymmetricState struct {
	sessionstate.SymmetricStateImpl
	recordedKeys [][]byte
}

func (t *testSymmetricState) MixKey(cipher cryptoutil.CipherAlgorithm, key []byte) {
	t.recordedKeys = append(t.recordedKeys, key)
	t.SymmetricStateImpl.MixKey(cipher, key)
}

func decodeX25519Key(t *testing.T, input string) *cryptoutil.X25519PrivateKey {
	raw, err := hex.DecodeString(input)
	if err != nil {
		t.Fatal(err)
	}
	c := ecdh.X25519()
	priv, err := c.NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &cryptoutil.X25519PrivateKey{
		Key: priv,
	}
}

func decodeEd25519Key(t *testing.T, input string) *cryptoutil.Ed25519PrivateKey {
	raw, err := hex.DecodeString(input)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.PrivateKey(raw)
	return &cryptoutil.Ed25519PrivateKey{
		Key: priv,
	}
}
