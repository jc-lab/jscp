package securechannel

import (
	"fmt"
	"github.com/jc-lab/jscp/go/cryptoutil"
	"github.com/jc-lab/jscp/go/payloadpb"
)

type Client struct {
	secureChannelBase

	BuildClientHello func(signedBuilder *payloadpb.ClientHelloSigned, clientHelloBuilder *payloadpb.ClientHello) error

	// OnServerHello need verify unencryptedServerHello.signed with unencryptedServerHello.signature
	OnServerHello func(
		unencryptedServerHello *payloadpb.UnencryptedServerHello,
		serverHelloSigned *payloadpb.ServerHelloSigned,
		encryptedServerHello *payloadpb.EncryptedServerHello,
	) error

	ephemeralKeyType payloadpb.KeyType
	staticKey        *cryptoutil.OpKeyPair
}

func NewClient(ephemeralKeyType payloadpb.KeyType, staticKey *cryptoutil.OpKeyPair) (*Client, error) {
	if ephemeralKeyType <= payloadpb.KeyType_KeyTypeDHStart || ephemeralKeyType >= payloadpb.KeyType_KeyTypeDHEnd {
		return nil, fmt.Errorf("illegal ephemeralKeyType: %v", ephemeralKeyType)
	}

	instance := &Client{
		secureChannelBase: secureChannelBase{
			serverMode:      false,
			cryptoAlgorithm: payloadpb.CryptoAlgorithm_CryptoAlgorithmAes,
		},
		ephemeralKeyType: ephemeralKeyType,
		staticKey:        staticKey,
	}
	instance.secureChannelBase.init()

	return instance, nil
}

func (i *Client) Handshake() (*Transfer, chan *HandshakeResult, error) {
	transfer, err := i.startHandshake()
	if err != nil {
		return nil, nil, err
	}
	return transfer, i.handshakeResultCh, nil
}

func (i *Client) OnMessage(payload *payloadpb.Payload) *Transfer {
	var err error

	transfer := &Transfer{}

	clientHelloBytes, ok := payload.Message.(*payloadpb.Payload_ClientHello)
	if ok {
		_ = clientHelloBytes
		return receiveResultAddAlert(transfer, &payloadpb.Alert{
			Code: payloadpb.AlertCode_AlertUnexpectedMessage,
		})
	}

	unencryptedServerHelloBytes, ok := payload.Message.(*payloadpb.Payload_UnencryptedServerHello)
	if ok {
		var unencryptedServerHello payloadpb.UnencryptedServerHello
		unencryptedServerHelloHash := cryptoutil.Hash(unencryptedServerHelloBytes.UnencryptedServerHello)
		if err = unencryptedServerHello.UnmarshalVT(unencryptedServerHelloBytes.UnencryptedServerHello); err != nil {
			return receiveResultSetError(transfer, err)
		}

		var serverHelloSigned payloadpb.ServerHelloSigned
		if err = serverHelloSigned.UnmarshalVT(unencryptedServerHello.Signed); err != nil {
			return receiveResultSetError(transfer, err)
		}

		remoteEphemeralKey, err := cryptoutil.UnmarshalFromPublicKeyProto(serverHelloSigned.EphemeralKey)
		if err != nil {
			return receiveResultSetError(transfer, err)
		}

		ephemeralMasterKey, err := i.localEphemeralKey.PrivateKey.DhAgreement(remoteEphemeralKey)
		if err != nil {
			return receiveResultSetError(transfer, err)
		}

		serverHelloKey := i.generateServerHelloKey(ephemeralMasterKey, i.clientHelloHash)
		encryptedServerHelloBytes, err := i.decrypt(payload.EncryptedMessage, serverHelloKey)
		if err != nil {
			return receiveResultSetError(transfer, err)
		}
		encryptedServerHelloHash := cryptoutil.Hash(encryptedServerHelloBytes)

		var encryptedServerHello payloadpb.EncryptedServerHello
		if err = encryptedServerHello.UnmarshalVT(encryptedServerHelloBytes); err != nil {
			return receiveResultSetError(transfer, err)
		}
		if i.OnServerHello != nil {
			if err = i.OnServerHello(&unencryptedServerHello, &serverHelloSigned, &encryptedServerHello); err != nil {
				return receiveResultSetError(transfer, err)
			}
		}

		i.ephemeralMasterKey = ephemeralMasterKey
		i.serverHelloKey = serverHelloKey
		i.setSessionKey(unencryptedServerHelloHash, encryptedServerHelloHash)

		handshakeResult := &HandshakeResult{}
		transfer.HandshakeResult = handshakeResult
		i.setHandshakeComplete(handshakeResult)

		return transfer
	}

	return i.secureChannelBase.OnMessage(transfer, payload)
}

func (i *Client) startHandshake() (*Transfer, error) {
	var err error

	transfer := &Transfer{}

	i.localEphemeralKey, err = cryptoutil.GenerateKeyPair(i.ephemeralKeyType)
	if err != nil {
		return nil, err
	}

	var signedBuilder payloadpb.ClientHelloSigned
	signedBuilder.EphemeralKey, err = i.localEphemeralKey.PublicKey.ToPublicKeyProto()
	if err != nil {
		return nil, err
	}

	clientHello := payloadpb.ClientHello{
		Version: 1,
	}

	if i.BuildClientHello != nil {
		if err = i.BuildClientHello(&signedBuilder, &clientHello); err != nil {
			return nil, err
		}
	}

	signedBuilderBytes, err := signedBuilder.MarshalVT()
	if err != nil {
		return nil, err
	}
	clientHello.Signed = signedBuilderBytes

	if i.staticKey != nil {
		clientHello.StaticKey, err = i.staticKey.PublicKey.ToPublicKeyProto()
		if err != nil {
			return nil, err
		}
		clientHello.Signature, err = i.staticKey.PrivateKey.Sign(signedBuilderBytes)
		if err != nil {
			return nil, err
		}
	}

	clientHelloBytes, err := clientHello.MarshalVT()
	i.clientHelloHash = cryptoutil.Hash(clientHelloBytes)

	transfer.Send = append(transfer.Send, &payloadpb.Payload{
		Message: &payloadpb.Payload_ClientHello{clientHelloBytes},
	})
	return transfer, nil
}
