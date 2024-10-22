package securechannel

import (
	"github.com/jc-lab/jscp/go/cryptoutil"
	"github.com/jc-lab/jscp/go/payloadpb"
)

type Server struct {
	secureChannelBase

	// OnClientHello need verify clientHello.StaticKey
	OnClientHello    func(clientHello *payloadpb.ClientHello) error
	BuildServerHello func(
		serverHelloSigned *payloadpb.ServerHelloSigned,
		encryptedServerHello *payloadpb.EncryptedServerHello,
	) error

	staticKey *cryptoutil.OpKeyPair
}

func NewServer(staticKey *cryptoutil.OpKeyPair) *Server {
	instance := &Server{
		secureChannelBase: secureChannelBase{
			serverMode:      true,
			cryptoAlgorithm: payloadpb.CryptoAlgorithm_CryptoAlgorithmAes,
		},
		staticKey: staticKey,
	}
	instance.secureChannelBase.init()

	return instance
}

func (i *Server) Handshake() chan *HandshakeResult {
	return i.handshakeResultCh
}

func (i *Server) OnMessage(payload *payloadpb.Payload) *Transfer {
	var err error

	transfer := &Transfer{}

	clientHelloBytes, ok := payload.Message.(*payloadpb.Payload_ClientHello)
	if ok {
		var clientHello payloadpb.ClientHello
		if err = clientHello.UnmarshalVT(clientHelloBytes.ClientHello); err != nil {
			return receiveResultSetError(transfer, err)
		}

		if len(clientHello.Signature) > 0 {
			clientStaticKey, err := cryptoutil.UnmarshalFromPublicKeyProto(clientHello.StaticKey)
			if err != nil {
				return receiveResultSetError(transfer, err)
			}
			if !clientStaticKey.Verify(clientHello.Signed, clientHello.Signature) {
				return receiveResultSetError(transfer, err)
			}
		}

		clientHelloHash := cryptoutil.HashSha256(clientHelloBytes.ClientHello)
		var signedClientHello payloadpb.ClientHelloSigned
		if err = signedClientHello.UnmarshalVT(clientHello.Signed); err != nil {
			return receiveResultSetError(transfer, err)
		}

		localEphemeralKey, err := cryptoutil.GenerateKeyPair(signedClientHello.EphemeralKey.KeyType)
		if err != nil {
			return receiveResultSetError(transfer, err)
		}

		remoteEphemeralKey, err := cryptoutil.UnmarshalFromPublicKeyProto(signedClientHello.EphemeralKey)
		if err != nil {
			return receiveResultSetError(transfer, err)
		}

		ephemeralMasterKey, err := localEphemeralKey.PrivateKey.DhAgreement(remoteEphemeralKey)
		if err != nil {
			return receiveResultSetError(transfer, err)
		}

		if i.OnClientHello != nil {
			if err = i.OnClientHello(&clientHello); err != nil {
				return receiveResultSetError(transfer, err)
			}
		}

		var serverHelloSigned payloadpb.ServerHelloSigned
		serverHelloSigned.CryptoAlgorithm = payloadpb.CryptoAlgorithm_CryptoAlgorithmAes
		serverHelloSigned.EphemeralKey, err = localEphemeralKey.PublicKey.ToPublicKeyProto()
		if err != nil {
			return receiveResultSetError(transfer, err)
		}

		var encryptedServerHello payloadpb.EncryptedServerHello
		if i.BuildServerHello != nil {
			if err = i.BuildServerHello(&serverHelloSigned, &encryptedServerHello); err != nil {
				return receiveResultSetError(transfer, err)
			}
		}

		serverHelloSignedBytes, err := serverHelloSigned.MarshalVT()
		if err != nil {
			return receiveResultSetError(transfer, err)
		}

		encryptedServerHelloBytes, err := encryptedServerHello.MarshalVT()
		if err != nil {
			return receiveResultSetError(transfer, err)
		}
		encryptedServerHelloHash := cryptoutil.HashSha256(encryptedServerHelloBytes)

		var unencryptedServerHello payloadpb.UnencryptedServerHello
		unencryptedServerHello.Signed = serverHelloSignedBytes
		if i.staticKey != nil {
			unencryptedServerHello.Signature, err = i.staticKey.PrivateKey.Sign(serverHelloSignedBytes)
			if err != nil {
				return receiveResultSetError(transfer, err)
			}
		}

		unencryptedServerHelloBytes, err := unencryptedServerHello.MarshalVT()
		if err != nil {
			return receiveResultSetError(transfer, err)
		}
		unencryptedServerHelloHash := cryptoutil.HashSha256(unencryptedServerHelloBytes)

		serverHelloKey := i.generateServerHelloKey(ephemeralMasterKey, clientHelloHash)
		ciphertext, err := i.encrypt(encryptedServerHelloBytes, serverHelloKey)
		if err != nil {
			return receiveResultSetError(transfer, err)
		}

		i.clientHelloHash = clientHelloHash
		i.localEphemeralKey = localEphemeralKey
		i.ephemeralMasterKey = ephemeralMasterKey
		i.serverHelloKey = serverHelloKey
		i.setSessionKey(unencryptedServerHelloHash, encryptedServerHelloHash)

		sendPayload := &payloadpb.Payload{
			Message:          &payloadpb.Payload_UnencryptedServerHello{unencryptedServerHelloBytes},
			EncryptedMessage: ciphertext,
		}
		transfer.Send = append(transfer.Send, sendPayload)

		handshakeResult := &HandshakeResult{}
		transfer.HandshakeResult = handshakeResult
		i.setHandshakeComplete(handshakeResult)

		return transfer
	}

	unencryptedServerHelloBytes, ok := payload.Message.(*payloadpb.Payload_UnencryptedServerHello)
	if ok {
		_ = unencryptedServerHelloBytes
		return receiveResultAddAlert(transfer, &payloadpb.Alert{
			Code: payloadpb.AlertCode_AlertUnexpectedMessage,
		})
	}

	return i.secureChannelBase.OnMessage(transfer, payload)
}
