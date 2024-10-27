import * as crypto from 'crypto';
import { Session } from './session';
import * as proto from './proto';
import { Ed25519Algorithm } from './crypto';
import { Channel } from './test/channel';

const ed25519 = new Ed25519Algorithm();

describe('communication tests', () => {
    for (let i = 0; i < 2; i++) {
        it(`no static - no static - ${(i === 0) ? 'without additional' : 'with additional'}`, async () => {
            const serverAdditionData = (i === 0) ? null : Buffer.from('i am server');
            const clientAdditionData = (i === 0) ? null : Buffer.from('i am client');
            const server = new Session(false, null);
            const client = new Session(true, null);

            client.send = (payload) => {
                setTimeout(() => server.handleReceive(payload), 0);
            };
            server.send = (payload) => {
                setTimeout(() => client.handleReceive(payload), 0);
            };

            const [clientResult, serverResult] = await Promise.all([
                client.handshake(clientAdditionData),
                server.handshake(serverAdditionData),
            ]);
            if (serverAdditionData && clientAdditionData) {
                expect(clientResult.peerAdditionalData).toBeInstanceOf(Uint8Array)
                expect(clientResult.peerAdditionalData).toBytesEqual(serverAdditionData);
                expect(serverResult.peerAdditionalData).toBeInstanceOf(Uint8Array)
                expect(serverResult.peerAdditionalData).toBytesEqual(clientAdditionData);
            }
        }, 500);
    }
});

describe('communication tests with signature', () => {
    for (let i = 0; i < 2; i++) {
        it(`static - static - ${(i === 0) ? 'without additional' : 'with additional'}`, async () => {
            const serverAdditionData = (i === 0) ? null : Buffer.from('i am server');
            const clientAdditionData = (i === 0) ? null : Buffer.from('i am client');

            const serverSigningKey = ed25519.generate();
            const server = new Session(false, serverSigningKey);

            const clientSigningKey = ed25519.generate();
            const client = new Session(true, clientSigningKey);

            client.send = (payload) => {
                setTimeout(() => server.handleReceive(payload), 0);
            };
            server.send = (payload) => {
                setTimeout(() => client.handleReceive(payload), 0);
            };

            const [clientResult, serverResult] = await Promise.all([
                client.handshake(clientAdditionData),
                server.handshake(serverAdditionData),
            ]);
            if (serverAdditionData && clientAdditionData) {
                expect(clientResult.peerAdditionalData).toBeInstanceOf(Uint8Array)
                expect(clientResult.peerAdditionalData).toBytesEqual(serverAdditionData);
                expect(serverResult.peerAdditionalData).toBeInstanceOf(Uint8Array)
                expect(serverResult.peerAdditionalData).toBytesEqual(clientAdditionData);
            }

            expect(clientResult.remotePublicKey?.marshalToProto()).toStrictEqual(serverSigningKey.public.marshalToProto())
            expect(serverResult.remotePublicKey?.marshalToProto()).toStrictEqual(clientSigningKey.public.marshalToProto())
        }, 500);
    }
});

describe('communication tests change algorithm', () => {
    for (let i = 0; i < 2; i++) {
        it(`no static - no static - ${(i === 0) ? 'without additional' : 'with additional'}`, async () => {
            const serverAdditionData = (i === 0) ? null : Buffer.from('i am server');
            const clientAdditionData = (i === 0) ? null : Buffer.from('i am client');
            const server = new Session(false, null);
            const client = new Session(true, null);

            let modified = false;

            client.send = (payload) => {
                if (!modified) {
                    modified = true;
                    const hello = proto.Hello.decode(payload.data);
                    hello.signed!.cipherAlgorithm = proto.CipherAlgorithm.CipherUnknown;
                    payload.data = proto.Hello.encode(hello).finish();
                }
                setTimeout(() => server.handleReceive(payload), 0);
            };
            server.send = (payload) => {
                setTimeout(() => client.handleReceive(payload), 0);
            };

            const [clientResult, serverResult] = await Promise.all([
                client.handshake(clientAdditionData),
                server.handshake(serverAdditionData),
            ]);
            if (serverAdditionData && clientAdditionData) {
                expect(clientResult.peerAdditionalData).toBeInstanceOf(Uint8Array)
                expect(clientResult.peerAdditionalData).toBytesEqual(serverAdditionData);
                expect(serverResult.peerAdditionalData).toBeInstanceOf(Uint8Array)
                expect(serverResult.peerAdditionalData).toBytesEqual(clientAdditionData);
            }
        }, 500);
    }
});

describe('communication tests with data', () => {
    it('data', async () => {
        const server = new Session(false, null);
        const client = new Session(true, null);

        let modified = false;

        client.send = (payload) => {
            if (!modified) {
                modified = true;
                const hello = proto.Hello.decode(payload.data);
                hello.signed!.cipherAlgorithm = proto.CipherAlgorithm.CipherUnknown;
                payload.data = proto.Hello.encode(hello).finish();
            }
            setTimeout(() => server.handleReceive(payload), 0);
        };
        server.send = (payload) => {
            setTimeout(() => client.handleReceive(payload), 0);
        };

        await Promise.all([
            client.handshake(null),
            server.handshake(null),
        ]);

        const serverCh = new Channel<Uint8Array>();
        server.onData = (data) => {
            serverCh.send(data);
        };
        const clientCh = new Channel<Uint8Array>();
        client.onData = (data) => {
            clientCh.send(data);
        };

        for (let i = 0; i < 100; i++) {
            let buf = crypto.randomBytes(32768);
            server.write(buf);
            let recv = await clientCh.receive();
            expect(recv).toBytesEqual(buf);

            buf = crypto.randomBytes(32768);
            client.write(buf);
            recv = await serverCh.receive();
            expect(recv).toBytesEqual(buf);
        }
    }, 5000);
});
