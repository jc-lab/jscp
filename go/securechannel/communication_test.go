package securechannel

import (
	"bytes"
	"github.com/jc-lab/jscp/go/payloadpb"
	"log"
	"math/rand"
	"testing"
	"time"
)

type TestContext struct {
	server             *Server
	client             *Client
	serverReceive      chan []byte
	clientReceive      chan []byte
	transferToClientCh chan *payloadpb.Payload
	transferToServerCh chan *payloadpb.Payload
}

func (tc *TestContext) ServerTransfer(r *Transfer, err error) {
	if r.Data != nil {
		tc.serverReceive <- r.Data
	}
	for _, payload := range r.Send {
		tc.transferToClientCh <- payload
	}
	if r.Finish {
		log.Printf("[Server] Closing: %+v", r.Error)
		close(tc.transferToClientCh)
	}
}

func (tc *TestContext) ClientTransfer(r *Transfer, err error) {
	if r.Data != nil {
		tc.clientReceive <- r.Data
	}
	for _, payload := range r.Send {
		tc.transferToServerCh <- payload
	}
	if r.Finish {
		log.Printf("[Client] Closing: %+v", r.Error)
		close(tc.transferToServerCh)
	}
}

func makePair(t *testing.T) *TestContext {
	var err error

	tc := &TestContext{
		server:             NewServer(nil),
		serverReceive:      make(chan []byte, 10),
		clientReceive:      make(chan []byte, 10),
		transferToClientCh: make(chan *payloadpb.Payload, 10),
		transferToServerCh: make(chan *payloadpb.Payload, 10),
	}

	go func() {
		for {
			p, ok := <-tc.transferToClientCh
			if !ok {
				break
			}
			tc.ClientTransfer(tc.client.OnMessage(p), nil)
		}
	}()

	go func() {
		for {
			p, ok := <-tc.transferToServerCh
			if !ok {
				break
			}
			tc.ServerTransfer(tc.server.OnMessage(p), nil)
		}
	}()

	tc.client, err = NewClient(payloadpb.KeyType_KeyTypeDHX25519, nil)

	go func() {
		handshakeCh := tc.server.Handshake()
		result := <-handshakeCh
		if result.Err != nil {
			t.Errorf("error in server during handshake failed: %+v", result.Err)
			return
		}
		log.Println("server handshake ok")
	}()
	transfer, handshakeCh, err := tc.client.Handshake()
	if err != nil {
		t.Errorf("error in client handshake start failed: %+v", err)
		return nil
	}
	tc.ClientTransfer(transfer, nil)

	result := <-handshakeCh
	if result.Err != nil {
		t.Errorf("error in client during handshake failed: %+v", result.Err)
		return nil
	}
	log.Println("client handshake ok")

	return tc
}

func TestHandshake(t *testing.T) {
	makePair(t)
}

func TestDataSmall(t *testing.T) {
	tc := makePair(t)

	tc.ServerTransfer(tc.server.Send([]byte("HELLO1")))
	select {
	case data := <-tc.clientReceive:
		if !bytes.Equal(data, []byte("HELLO1")) {
			t.Errorf("Expected HELLO1, got %s", data)
		}
	case <-time.After(10 * time.Millisecond):
		t.Error("Timeout waiting for HELLO1")
	}

	tc.ServerTransfer(tc.server.Send([]byte("HELLO2")))
	select {
	case data := <-tc.clientReceive:
		if !bytes.Equal(data, []byte("HELLO2")) {
			t.Errorf("Expected HELLO2, got %s", data)
		}
	case <-time.After(1 * time.Millisecond):
		t.Error("Timeout waiting for HELLO2")
	}

	tc.ClientTransfer(tc.client.Send([]byte("WORLD1")))
	select {
	case data := <-tc.serverReceive:
		if !bytes.Equal(data, []byte("WORLD1")) {
			t.Errorf("Expected WORLD1, got %s", data)
		}
	case <-time.After(1 * time.Millisecond):
		t.Error("Timeout waiting for WORLD1")
	}
	tc.ClientTransfer(tc.client.Send([]byte("WORLD2")))
	select {
	case data := <-tc.serverReceive:
		if !bytes.Equal(data, []byte("WORLD2")) {
			t.Errorf("Expected WORLD2, got %s", data)
		}
	case <-time.After(1 * time.Millisecond):
		t.Error("Timeout waiting for WORLD2")
	}
}

func TestDataRandomLarge(t *testing.T) {
	tc := makePair(t)

	r1 := make(chan struct{})
	go func() {
		defer close(r1)
		dataSize := rand.Intn(32768)
		buffer := append([]byte("HELLO"), make([]byte, dataSize)...)
		tc.ServerTransfer(tc.server.Send(buffer))

		select {
		case data := <-tc.clientReceive:
			if !bytes.Equal(data, buffer) {
				t.Errorf("Expected %v, got %v", buffer, data)
			}
		case <-time.After(1 * time.Millisecond):
			t.Error("Timeout waiting for server message")
		}
	}()

	r2 := make(chan struct{})
	go func() {
		defer close(r2)
		dataSize := rand.Intn(32768)
		buffer := append([]byte("HELLO"), make([]byte, dataSize)...)
		tc.ClientTransfer(tc.client.Send(buffer))

		select {
		case data := <-tc.serverReceive:
			if !bytes.Equal(data, buffer) {
				t.Errorf("Expected %v, got %v", buffer, data)
			}
		case <-time.After(1 * time.Millisecond):
			t.Error("Timeout waiting for client message")
		}
	}()

	<-r1
	<-r2
}
