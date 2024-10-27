package session

import (
	"fmt"
	"github.com/jc-lab/jscp/go/cryptoutil"
	"github.com/jc-lab/jscp/go/payloadpb"
	"github.com/jc-lab/jscp/go/sessionstate"
	"github.com/pkg/errors"
	"io"
)

type HandshakeResult struct {
	Error error

	RemotePublicKey    cryptoutil.SignaturePublicKey
	PeerAdditionalData []byte
}

type SendFunc func(payload *payloadpb.Payload)

type Session struct {
	initiator bool
	sendFunc  SendFunc
	recvCh    chan []byte

	signatureKeyPair cryptoutil.SignaturePrivateKey

	handshakeAdditionalData []byte

	remotePublicKey cryptoutil.SignaturePublicKey
	handshakeResult *HandshakeResult
	handshakeCh     chan *HandshakeResult

	localState  *sessionstate.SymmetricState
	remoteState *sessionstate.SymmetricState

	ephemeralKeyPair         *cryptoutil.DHKeyPair
	remoteEphemeralPublicKey cryptoutil.DHPublicKey

	availableEphemeralKeyAlgorithms []payloadpb.DHAlgorithm
	availableCipherAlgorithms       []payloadpb.CipherAlgorithm
}

func NewSession(initiator bool, sendFunc SendFunc, signatureKeyPair cryptoutil.SignaturePrivateKey) *Session {
	return &Session{
		initiator: initiator,
		sendFunc:  sendFunc,
		recvCh:    make(chan []byte, 1),

		signatureKeyPair: signatureKeyPair,
		handshakeCh:      make(chan *HandshakeResult, 1),

		localState:  sessionstate.NewSymmetricState(),
		remoteState: sessionstate.NewSymmetricState(),

		availableEphemeralKeyAlgorithms: []payloadpb.DHAlgorithm{
			payloadpb.DHAlgorithm_DHX25519,
		},
		availableCipherAlgorithms: []payloadpb.CipherAlgorithm{
			payloadpb.CipherAlgorithm_CipherAesGcm,
		},
	}
}

func (s *Session) HandleReceive(payload *payloadpb.Payload) error {
	switch payload.PayloadType {
	case payloadpb.PayloadType_PayloadHello:
		return s.handleHello(payload.Data, false)
	case payloadpb.PayloadType_PayloadHelloWithChangeAlgorithm:
		return s.handleHello(payload.Data, true)
	case payloadpb.PayloadType_PayloadEncryptedMessage:
		return s.handleEncryptedMessage(payload.Data)
	default:
		return fmt.Errorf("invalid payload: %+v", payload.PayloadType)
	}
}

func (s *Session) Handshake(additionalData []byte) (chan *HandshakeResult, error) {
	s.handshakeAdditionalData = additionalData
	s.handshakeResult = &HandshakeResult{}
	if s.initiator {
		go func() {
			err := s.sendHello(false)
			if err != nil {
				s.handshakeResult.Error = err
				s.emitHandshakeResult()
			}
		}()
	}
	return s.handshakeCh, nil
}

func (s *Session) Write(data []byte) error {
	var encryptedMessage payloadpb.EncryptedMessage
	encryptedMessage.Data = data

	raw, err := encryptedMessage.MarshalVT()
	if err != nil {
		return err
	}

	ciphertext, err := s.localState.EncryptWithAd(raw, nil)
	if err != nil {
		return err
	}

	payload := &payloadpb.Payload{}
	payload.PayloadType = payloadpb.PayloadType_PayloadEncryptedMessage
	payload.Data = ciphertext
	s.sendFunc(payload)
	return nil
}

func (s *Session) Read() ([]byte, error) {
	data, ok := <-s.recvCh
	if !ok {
		return nil, io.EOF
	}
	return data, nil
}

func (s *Session) emitHandshakeResult() {
	s.handshakeResult.RemotePublicKey = s.remotePublicKey
	s.handshakeCh <- s.handshakeResult
	close(s.handshakeCh)
}

func (s *Session) handleHello(payloadRaw []byte, retry bool) error {
	var handshakeFinish bool
	var sendRetry bool

	var hello payloadpb.Hello
	if err := hello.UnmarshalVT(payloadRaw); err != nil {
		return fmt.Errorf("failed to unmarshal Hello: %w", err)
	}

	var helloBytes payloadpb.HelloBytes
	if err := helloBytes.UnmarshalVT(payloadRaw); err != nil {
		return fmt.Errorf("failed to unmarshal HelloBytes: %w", err)
	}

	var helloSignedBytes payloadpb.HelloSignedBytes
	if err := helloSignedBytes.UnmarshalVT(helloBytes.Signed); err != nil {
		return fmt.Errorf("failed to unmarshal HelloSignedBytes: %w", err)
	}

	if hello.Signed.PublicKey != nil {
		signatureAlgorithm, err := cryptoutil.GetSignatureAlgorithm(hello.Signed.PublicKey.Algorithm)
		if err != nil {
			return err
		}
		publicKey, err := signatureAlgorithm.UnmarshalPublicKey(hello.Signed.PublicKey.Data)
		if err != nil {
			return fmt.Errorf("failed to unmarshal public key: %w", err)
		}

		verified, err := publicKey.Verify(helloBytes.Signed, helloBytes.Signature)
		if err != nil {
			return fmt.Errorf("failed to verify signature: %w", err)
		}
		if !verified {
			return errors.New("payload verification failed")
		}

		s.remotePublicKey = publicKey
	}

	// Check cipher algorithm compatibility
	if !contains(s.availableCipherAlgorithms, hello.Signed.CipherAlgorithm) {
		if retry {
			return errors.New("any cipher not supported")
		}

		s.availableCipherAlgorithms = filterAlgorithms(s.availableCipherAlgorithms, hello.Signed.SupportCipher)
		if len(s.availableCipherAlgorithms) == 0 {
			return errors.New("any cipher not supported")
		}

		sendRetry = true
	}

	// Check DH algorithm compatibility
	if !contains(s.availableEphemeralKeyAlgorithms, hello.Signed.EphemeralKey.Algorithm) {
		if retry {
			return errors.New("any dh not supported")
		}

		s.availableEphemeralKeyAlgorithms = filterAlgorithms(s.availableEphemeralKeyAlgorithms, hello.Signed.SupportDh)
		if len(s.availableEphemeralKeyAlgorithms) == 0 {
			return errors.New("any dh not supported")
		}

		sendRetry = true
	}

	if retry || sendRetry {
		s.handshakeResult = &HandshakeResult{}
		s.localState = sessionstate.NewSymmetricState()
		s.remoteState = sessionstate.NewSymmetricState()
		s.ephemeralKeyPair = nil

		if sendRetry {
			return s.sendHello(true)
		}
	}

	// Mix version into hash
	s.remoteState.MixHash(encodeUint32(hello.Version))

	if hello.Signed.PublicKey != nil {
		s.remoteState.MixHash(helloSignedBytes.PublicKey)
	}

	dhAlgorithm, err := cryptoutil.GetDHAlgorithm(hello.Signed.EphemeralKey.Algorithm)
	if err != nil {
		return err
	}
	remoteEphemeralPublicKey, err := dhAlgorithm.UnmarshalPublicKey(hello.Signed.EphemeralKey.Data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal ephemeral public key: %w", err)
	}
	s.remoteEphemeralPublicKey = remoteEphemeralPublicKey

	if s.ephemeralKeyPair != nil {
		cipherAlgorithm, err := cryptoutil.GetCipherAlgorithm(hello.Signed.CipherAlgorithm)
		if err != nil {
			return err
		}
		sharedKey, err := s.ephemeralKeyPair.Private.DH(s.remoteEphemeralPublicKey)
		if err != nil {
			return err
		}
		s.localState.MixKey(cipherAlgorithm, sharedKey)
		s.remoteState.MixKey(cipherAlgorithm, sharedKey)
		handshakeFinish = true
	} else {
		s.remoteState.MixHash(helloSignedBytes.EphemeralKey)
	}

	if len(hello.Signed.Additional) > 0 {
		peerAdditionalData, err := s.remoteState.MixHashAndDecrypt(hello.Signed.Additional)
		if err != nil {
			return fmt.Errorf("failed to decrypt additional data: %w", err)
		}
		s.handshakeResult.PeerAdditionalData = peerAdditionalData
	}

	if len(helloBytes.Signature) > 0 {
		s.remoteState.MixHash(helloBytes.Signature)
	}

	if handshakeFinish {
		s.emitHandshakeResult()
	} else {
		if err := s.sendHello(false); err != nil {
			return fmt.Errorf("failed to send hello: %w", err)
		}
	}

	return nil
}

func (s *Session) handleEncryptedMessage(payloadRaw []byte) error {
	plaintext, err := s.remoteState.DecryptWithAd(payloadRaw, nil)
	if err != nil {
		return err
	}

	var encryptedMessage payloadpb.EncryptedMessage
	if err = encryptedMessage.UnmarshalVT(plaintext); err != nil {
		return err
	}

	s.recvCh <- encryptedMessage.Data

	return nil
}

func (s *Session) sendHello(changeAlgorithm bool) error {
	handshakeFinish := false

	dhAlgorithm, err := cryptoutil.GetDHAlgorithm(s.availableEphemeralKeyAlgorithms[0])
	if err != nil {
		return err
	}
	cipherAlgorithm, err := cryptoutil.GetCipherAlgorithm(s.availableCipherAlgorithms[0])
	if err != nil {
		return err
	}

	hello := &payloadpb.HelloBytes{
		Version:   1,
		Signed:    nil,
		Signature: nil,
	}
	s.localState.MixHash(encodeUint32(hello.Version))

	helloSigned := &payloadpb.HelloSignedBytes{
		SupportDh: []payloadpb.DHAlgorithm{
			payloadpb.DHAlgorithm_DHX25519,
		},
		SupportCipher: []payloadpb.CipherAlgorithm{
			payloadpb.CipherAlgorithm_CipherAesGcm,
		},
		CipherAlgorithm: cipherAlgorithm.GetType(),
		PublicKey:       nil,
		EphemeralKey:    nil,
		Additional:      s.handshakeAdditionalData,
	}

	if s.signatureKeyPair != nil {
		publicKeyProto, err := s.signatureKeyPair.GetPublic().MarshalToProto()
		if err != nil {
			return err
		}
		helloSigned.PublicKey, err = publicKeyProto.MarshalVT()
		if err != nil {
			return err
		}
		s.localState.MixHash(helloSigned.PublicKey)
	}

	if s.ephemeralKeyPair == nil {
		var err error
		s.ephemeralKeyPair, err = dhAlgorithm.Generate()
		if err != nil {
			return fmt.Errorf("failed to generate ephemeral key pair: %w", err)
		}
	}

	ephemeralPublicKey := &payloadpb.DHPublicKey{
		Algorithm: dhAlgorithm.GetType(),
		Data:      s.ephemeralKeyPair.Public.Marshal(),
	}
	ephemeralKeyBytes, err := ephemeralPublicKey.MarshalVT()
	if err != nil {
		return fmt.Errorf("failed to marshal ephemeral public key: %w", err)
	}
	helloSigned.EphemeralKey = ephemeralKeyBytes

	if s.remoteEphemeralPublicKey != nil {
		sharedKey, err := s.ephemeralKeyPair.Private.DH(s.remoteEphemeralPublicKey)
		if err != nil {
			return err
		}
		s.localState.MixKey(cipherAlgorithm, sharedKey)
		s.remoteState.MixKey(cipherAlgorithm, sharedKey)
		handshakeFinish = true
	} else {
		s.localState.MixHash(helloSigned.EphemeralKey)
	}

	if len(s.handshakeAdditionalData) > 0 {
		encrypted, err := s.localState.EncryptAndMixHash(s.handshakeAdditionalData, false)
		if err != nil {
			return fmt.Errorf("failed to encrypt additional data: %w", err)
		}
		helloSigned.Additional = encrypted
	}

	signedBytes, err := helloSigned.MarshalVT()
	if err != nil {
		return fmt.Errorf("failed to marshal HelloSignedBytes: %w", err)
	}
	hello.Signed = signedBytes

	if s.signatureKeyPair != nil {
		if priv, ok := s.signatureKeyPair.(interface{ Sign([]byte) ([]byte, error) }); ok {
			signature, err := priv.Sign(hello.Signed)
			if err != nil {
				return fmt.Errorf("failed to sign hello: %w", err)
			}
			hello.Signature = signature
			s.localState.MixHash(hello.Signature)
		}
	}

	if handshakeFinish {
		s.emitHandshakeResult()
	}

	payloadType := payloadpb.PayloadType_PayloadHello
	if changeAlgorithm {
		payloadType = payloadpb.PayloadType_PayloadHelloWithChangeAlgorithm
	}

	helloBytes, err := hello.MarshalVT()
	if err != nil {
		return fmt.Errorf("failed to marshal HelloBytes: %w", err)
	}

	s.sendFunc(&payloadpb.Payload{
		PayloadType: payloadType,
		Data:        helloBytes,
	})

	return nil
}

func contains[T comparable](slice []T, item T) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func filterAlgorithms[T comparable](available []T, supported []T) []T {
	result := make([]T, 0)
	for _, v := range available {
		if contains(supported, v) {
			result = append(result, v)
		}
	}
	return result
}
