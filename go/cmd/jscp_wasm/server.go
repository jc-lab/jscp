package main

import (
	"github.com/jc-lab/go-wasm-helper/whelper"
	"github.com/jc-lab/go-wasm-helper/wret"
	"github.com/jc-lab/jscp/go/securechannel"
)

//export newServer
func newServer(staticKeyParam whelper.RefId) whelper.RefId {
	staticKey, err := paramToStaticKey(staticKeyParam)
	if err != nil {
		return wret.ReturnError(err)
	}

	server := securechannel.NewServer(staticKey)
	return wret.ReturnObject(server)
}

//// OnClientHello need verify clientHello.StaticKey
//	OnClientHello    func(clientHello *payloadpb.ClientHello) error
//	BuildServerHello func(
//		serverHelloSigned *payloadpb.ServerHelloSigned,
//		encryptedServerHello *payloadpb.EncryptedServerHello,
//	) error

// Handshake() chan *HandshakeResult

// OnMessage(payload *payloadpb.Payload)
