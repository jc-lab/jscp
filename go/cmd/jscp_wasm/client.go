package main

import (
	"github.com/jc-lab/go-wasm-helper/whelper"
	"github.com/jc-lab/go-wasm-helper/wret"
	"github.com/jc-lab/jscp/go/payloadpb"
	"github.com/jc-lab/jscp/go/securechannel"
)

//export clientNew
func clientNew(ephemeralKeyType uint32, staticKeyParam whelper.RefId) whelper.RefId {
	staticKey, err := paramToStaticKey(staticKeyParam)
	if err != nil {
		return wret.ReturnError(err)
	}

	server, err := securechannel.NewClient(payloadpb.KeyType(ephemeralKeyType), staticKey)
	if err != nil {
		return wret.ReturnError(err)
	}
	return wret.ReturnObject(server)
}

// BuildClientHello func(signedBuilder *payloadpb.ClientHelloSigned, clientHelloBuilder *payloadpb.ClientHello) error
//
//	// OnServerHello need verify unencryptedServerHello.signed with unencryptedServerHello.signature
//	OnServerHello func(
//		unencryptedServerHello *payloadpb.UnencryptedServerHello,
//		serverHelloSigned *payloadpb.ServerHelloSigned,
//		encryptedServerHello *payloadpb.EncryptedServerHello,
//	) error

// Handshake() (*Transfer, chan *HandshakeResult, error)

/// OnMessage(payload *payloadpb.Payload) *Transfer

// Send(data []byte) (*Transfer, error)
