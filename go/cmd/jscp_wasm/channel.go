package main

import (
	"github.com/jc-lab/go-wasm-helper/whelper"
	"github.com/jc-lab/go-wasm-helper/wret"
	"github.com/jc-lab/jscp/go/payloadpb"
	"github.com/jc-lab/jscp/go/securechannel"
	"google.golang.org/protobuf/proto"
)

//export secureChannelSend
func secureChannelSend(channelRef whelper.RefId, data whelper.RefId) whelper.RefId {
	channel := channelRef.GetObject().(securechannel.Channel)
	transfer, err := channel.Send(data.GetBuffer())
	if err != nil {
		return wret.ReturnError(err)
	}
	return encodeTransfer(transfer)
}

//export secureChannelOnMessage
func secureChannelOnMessage(channelRef whelper.RefId, payloadRef whelper.RefId) whelper.RefId {
	var payload payloadpb.Payload
	if err := proto.Unmarshal(payloadRef.GetBuffer(), &payload); err != nil {
		return wret.ReturnError(err)
	}
	channel := channelRef.GetObject().(securechannel.Channel)
	transfer := channel.OnMessage(&payload)
	return encodeTransfer(transfer)
}
