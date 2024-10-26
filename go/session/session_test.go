package session

import (
	"bytes"
	"github.com/jc-lab/jscp/go/cryptoutil"
	"github.com/jc-lab/jscp/go/payloadpb"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCommunication(t *testing.T) {
	testCases := []struct {
		name             string
		serverAdditional []byte
		clientAdditional []byte
		expectAdditional bool
		useSignature     bool
	}{
		{
			name:             "no static - no static - without additional",
			serverAdditional: nil,
			clientAdditional: nil,
			expectAdditional: false,
		},
		{
			name:             "no static - no static - with additional",
			serverAdditional: []byte("i am server"),
			clientAdditional: []byte("i am client"),
			expectAdditional: true,
		},

		{
			name:             "static - static - without additional",
			serverAdditional: nil,
			clientAdditional: nil,
			expectAdditional: false,
			useSignature:     true,
		},
		{
			name:             "static - static - with additional",
			serverAdditional: []byte("i am server"),
			clientAdditional: []byte("i am client"),
			expectAdditional: true,
			useSignature:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var serverPrivateKey cryptoutil.SignaturePrivateKey
			var clientPrivateKey cryptoutil.SignaturePrivateKey

			if tc.useSignature {
				var err error
				ed25519Algorithm := &cryptoutil.Ed25519Algorithm{}
				if serverPrivateKey, err = ed25519Algorithm.Generate(); err != nil {
					t.Fatal(err)
				}
				if clientPrivateKey, err = ed25519Algorithm.Generate(); err != nil {
					t.Fatal(err)
				}
			}

			// Create channels for communication between client and server
			clientToServer := make(chan *payloadpb.Payload, 1)
			serverToClient := make(chan *payloadpb.Payload, 1)

			// Create server and client with their respective send functions
			server := NewSession(false, func(payload *payloadpb.Payload) {
				serverToClient <- payload
			}, serverPrivateKey)

			client := NewSession(true, func(payload *payloadpb.Payload) {
				clientToServer <- payload
			}, clientPrivateKey)

			// Start goroutines to handle message passing
			go func() {
				for payload := range serverToClient {
					err := client.HandleReceive(payload)
					if err != nil {
						t.Errorf("client.HandleReceive error: %v", err)
					}
				}
			}()

			go func() {
				for payload := range clientToServer {
					err := server.HandleReceive(payload)
					if err != nil {
						t.Errorf("server.HandleReceive error: %v", err)
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

			if tc.useSignature {
				compareSignaturePublicKey(t, serverPrivateKey.GetPublic(), clientResult.RemotePublicKey)
				compareSignaturePublicKey(t, clientPrivateKey.GetPublic(), serverResult.RemotePublicKey)
			}

			// Close channels
			close(clientToServer)
			close(serverToClient)
		})
	}
}

func compareSignaturePublicKey(t *testing.T, expected cryptoutil.SignaturePublicKey, actual cryptoutil.SignaturePublicKey) {
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
