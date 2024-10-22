package main

import (
	"github.com/jc-lab/go-wasm-helper/whelper"
	"github.com/jc-lab/go-wasm-helper/wret"
	"github.com/jc-lab/jscp/go/cryptoutil"
	"github.com/jc-lab/jscp/go/payloadpb"
	"github.com/jc-lab/jscp/go/securechannel"
)

//go:generate msgp

type HandshakeResult struct {
	Error []byte // []byte Error
}

type TransferBridge struct {
	Send            [][]byte // []*payloadpb.Payload
	Finish          bool
	HandshakeResult *HandshakeResult
	Data            []byte
	Error           []byte // []byte Error
}

func encodeTransfer(t *securechannel.Transfer) whelper.RefId {
	var bridge TransferBridge
	var err error

	for _, payload := range t.Send {
		b, err := payload.MarshalVT()
		if err != nil {
			return wret.ReturnError(err)
		}
		bridge.Send = append(bridge.Send, b)
	}
	bridge.Finish = t.Finish

	if t.HandshakeResult != nil {
		bridge.HandshakeResult = &HandshakeResult{}
		if t.HandshakeResult.Err != nil {
			bridge.HandshakeResult.Error, err = (&wret.Error{
				Message: t.Error.Error(),
			}).MarshalMsg(nil)
		}
	}

	if t.Error != nil {
		bridge.Error, err = (&wret.Error{
			Message: t.Error.Error(),
		}).MarshalMsg(nil)
	}
	bridge.Data = t.Data
	b, err := bridge.MarshalMsg(nil)
	if err != nil {
		return wret.ReturnError(err)
	}
	return wret.ReturnBuffer(b)
}

func paramToStaticKey(staticKeyParam whelper.RefId) (*cryptoutil.OpKeyPair, error) {
	var staticKeyBytes []byte
	if !staticKeyParam.IsVoid() {
		staticKeyBytes = staticKeyParam.GetBuffer()
	}
	if len(staticKeyBytes) > 0 {
		privateKey := &payloadpb.PrivateKey{}
		if err := privateKey.UnmarshalVT(staticKeyBytes); err != nil {
			return nil, err
		}
		return cryptoutil.UnmarshalFromPrivateKeyProto(privateKey)
	}
	return nil, nil
}
