package securechannel

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"github.com/jc-lab/jscp/go/cryptoutil"
	"github.com/jc-lab/jscp/go/payloadpb"
	"sync"
)

type Channel interface {
	OnMessage(payload *payloadpb.Payload) *Transfer
	Send(data []byte) (*Transfer, error)
}

type Transfer struct {
	Send   []*payloadpb.Payload
	Finish bool

	HandshakeResult *HandshakeResult

	Data []byte

	Error error
}

type HandshakeResult struct {
	Err error
}

type CryptoUtils struct{}

type secureChannelBase struct {
	serverMode bool

	handshakeResultCh chan *HandshakeResult

	localEphemeralKey  *cryptoutil.OpKeyPair
	ephemeralMasterKey []byte
	clientHelloHash    []byte
	serverHelloKey     []byte
	sessionKey         []byte
	localEncryptKey    []byte
	localLastSeqNum    int64
	remoteEncryptKey   []byte
	remoteLastSeqNum   int64
	cryptoAlgorithm    payloadpb.CryptoAlgorithm
	mu                 sync.Mutex
}

func (sc *secureChannelBase) init() {
	sc.handshakeResultCh = make(chan *HandshakeResult)
}

func (sc *secureChannelBase) OnMessage(result *Transfer, payload *payloadpb.Payload) *Transfer {
	if payload.EncryptedMessage != nil {
		plaintext, err := sc.decrypt(payload.EncryptedMessage, nil)
		if err != nil {
			return receiveResultSetError(result, err)
		}
		result.Data = plaintext
	}
	return result
}

func (sc *secureChannelBase) Send(data []byte) (*Transfer, error) {
	encryptedMessage, err := sc.encrypt(data, nil)
	if err != nil {
		return nil, err
	}
	t := &Transfer{}
	t.Send = append(t.Send, &payloadpb.Payload{
		EncryptedMessage: encryptedMessage,
	})
	return t, nil
}

func (sc *secureChannelBase) setHandshakeComplete(result *HandshakeResult) {
	sc.handshakeResultCh <- result
	close(sc.handshakeResultCh)
}

func (sc *secureChannelBase) generateServerHelloKey(ephemeralMasterKey []byte, clientHelloHash []byte) []byte {
	serverHelloKey := cryptoutil.HkdfSha256(ephemeralMasterKey, clientHelloHash, []byte("SERVER_HELLO"), 32)
	return serverHelloKey
}

func (sc *secureChannelBase) setSessionKey(unencryptedServerHelloHash, encryptedServerHelloHash []byte) {
	sessionKey := cryptoutil.HkdfSha256(sc.serverHelloKey, append(unencryptedServerHelloHash, encryptedServerHelloHash...), []byte("SESSION"), 32)
	sc.sessionKey = sessionKey

	serverEncryptKey := cryptoutil.HkdfSha256(sessionKey, nil, []byte("SERVER"), 32)
	clientEncryptKey := cryptoutil.HkdfSha256(sessionKey, nil, []byte("CLIENT"), 32)

	if sc.serverMode {
		sc.localEncryptKey = serverEncryptKey
		sc.remoteEncryptKey = clientEncryptKey
	} else {
		sc.localEncryptKey = clientEncryptKey
		sc.remoteEncryptKey = serverEncryptKey
	}
}

func (sc *secureChannelBase) encrypt(plaintext []byte, specificKey []byte) (*payloadpb.EncryptedMessage, error) {
	var err error
	var seqNum int64

	key := sc.localEncryptKey
	if specificKey == nil {
		seqNum = sc.localLastSeqNum + 1
		sc.localLastSeqNum = seqNum
	} else {
		key = specificKey
	}

	var compressionInfo payloadpb.CompressionInfo
	compressionInfo.Type = payloadpb.CompressionType_CompressionNone
	if len(plaintext) > 64 {
		compressionInfo.Type = payloadpb.CompressionType_CompressionZlib
	}

	compressed := sc.compress(&compressionInfo, plaintext)

	encryptedMessage := &payloadpb.EncryptedMessage{}
	if encryptedMessage.CompressionInfo, err = compressionInfo.MarshalVT(); err != nil {
		return nil, err
	}

	authData := sc.makeAuthData(seqNum, encryptedMessage)
	err = cryptoutil.Encrypt(sc.cryptoAlgorithm, encryptedMessage, key, authData, compressed)
	return encryptedMessage, err
}

func (sc *secureChannelBase) decrypt(encryptedMessage *payloadpb.EncryptedMessage, specificKey []byte) ([]byte, error) {
	var seqNum int64

	key := sc.remoteEncryptKey
	if specificKey == nil {
		seqNum = sc.remoteLastSeqNum + 1
	} else {
		key = specificKey
	}

	authData := sc.makeAuthData(seqNum, encryptedMessage)

	plaintext, err := cryptoutil.Decrypt(sc.cryptoAlgorithm, key, authData, encryptedMessage)
	if err != nil {
		return nil, err
	}

	if specificKey == nil {
		sc.remoteLastSeqNum = seqNum
	}

	var compressionInfo payloadpb.CompressionInfo
	if err = compressionInfo.UnmarshalVT(encryptedMessage.CompressionInfo); err != nil {
		return nil, err
	}
	return sc.decompress(&compressionInfo, plaintext)
}

func (sc *secureChannelBase) makeAuthData(sequenceNumber int64, encryptedMessage *payloadpb.EncryptedMessage) []byte {
	return append(binary.BigEndian.AppendUint64(nil, uint64(sequenceNumber)), encryptedMessage.CompressionInfo...)
}

func (sc *secureChannelBase) compress(info *payloadpb.CompressionInfo, input []byte) []byte {
	if info.Type != payloadpb.CompressionType_CompressionZlib {
		return input
	}

	var output bytes.Buffer
	writer, _ := flate.NewWriter(&output, flate.DefaultCompression)
	defer writer.Close()

	writer.Write(input)
	writer.Close()

	return output.Bytes()
}

func (sc *secureChannelBase) decompress(info *payloadpb.CompressionInfo, input []byte) ([]byte, error) {
	if info.Type != payloadpb.CompressionType_CompressionZlib {
		return input, nil
	}

	reader := flate.NewReader(bytes.NewReader(input))

	var output bytes.Buffer
	if _, err := output.ReadFrom(reader); err != nil {
		reader.Close()

		return nil, err
	}

	err := reader.Close()
	if err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
