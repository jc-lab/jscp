import * as crypto from 'crypto';
import { Session } from './session';
import {
    type PrivateKey,
    type CipherAlgorithm,
    type Bytes,
    Ed25519Algorithm,
    X25519Algorithm,
} from './crypto';
import { Channel } from './test/channel';
import { CURVES, ECCDHSpecificAlgorithm } from './crypto/ecc';
import { SymmetricState } from './symmetricstate';
import * as proto from './proto';

const textEncoder = new TextEncoder();

interface TestCase {
    name: string;
    serverAdditional: Uint8Array | null;
    clientAdditional: Uint8Array | null;
    expectAdditional: boolean;
    serverUseSignature?: boolean;
    clientUseSignature?: boolean;
    serverUseDHSignature?: string;
    clientUseDHSignature?: string;
}

const testCases: TestCase[] = [
    {
        name: 'no_static-no_static-wo_additional',
        serverAdditional: null,
        clientAdditional: null,
        expectAdditional: false,
    },
    {
        name: 'no_static-no_static-with_additional',
        serverAdditional: textEncoder.encode('i am server'),
        clientAdditional: textEncoder.encode('i am client'),
        expectAdditional: true,
    },
    {
        name: 'static(signature)-static(signature)-wo_additional',
        serverAdditional: null,
        clientAdditional: null,
        expectAdditional: false,
        serverUseSignature: true,
        clientUseSignature: true,
    },
    {
        name: 'static(signature)-static(signature)-with_additional',
        serverAdditional: textEncoder.encode('i am server'),
        clientAdditional: textEncoder.encode('i am client'),
        expectAdditional: true,
        serverUseSignature: true,
        clientUseSignature: true,
    },
    {
        name: 'static(x25519)-static(x25519)-wo_additional',
        serverAdditional: null,
        clientAdditional: null,
        expectAdditional: false,
        serverUseSignature: true,
        clientUseSignature: true,
        serverUseDHSignature: 'x25519',
        clientUseDHSignature: 'x25519',
    },
    {
        name: 'static(x25519)-static(x25519)-with_additional',
        serverAdditional: textEncoder.encode('i am server'),
        clientAdditional: textEncoder.encode('i am client'),
        expectAdditional: true,
        serverUseSignature: true,
        clientUseSignature: true,
        serverUseDHSignature: 'x25519',
        clientUseDHSignature: 'x25519',
    },
    {
        name: 'static(p256)-static(p256)-wo_additional',
        serverAdditional: null,
        clientAdditional: null,
        expectAdditional: false,
        serverUseSignature: true,
        clientUseSignature: true,
        serverUseDHSignature: 'p256',
        clientUseDHSignature: 'p256',
    },
    {
        name: 'static(p256)-static(p256)-with_additional',
        serverAdditional: textEncoder.encode('i am server'),
        clientAdditional: textEncoder.encode('i am client'),
        expectAdditional: true,
        serverUseSignature: true,
        clientUseSignature: true,
        serverUseDHSignature: 'p256',
        clientUseDHSignature: 'p256',
    },
    {
        name: 'no_static(p256)-static(p256)-with_additional',
        serverAdditional: textEncoder.encode('i am server'),
        clientAdditional: textEncoder.encode('i am client'),
        expectAdditional: true,
        serverUseSignature: false,
        clientUseSignature: true,
        serverUseDHSignature: '',
        clientUseDHSignature: 'p256',
    },
    {
        name: 'static(p256)-no_static(p256)-with_additional',
        serverAdditional: textEncoder.encode('i am server'),
        clientAdditional: textEncoder.encode('i am client'),
        expectAdditional: true,
        serverUseSignature: true,
        clientUseSignature: false,
        serverUseDHSignature: 'p256',
        clientUseDHSignature: '',
    },
    {
        name: 'data communication',
        serverAdditional: textEncoder.encode('i am server'),
        clientAdditional: textEncoder.encode('i am client'),
        expectAdditional: true,
        serverUseSignature: true,
        clientUseSignature: true,
        serverUseDHSignature: 'p256',
        clientUseDHSignature: 'p256',
    },
];

async function generateSignatureKey(useDH: string | undefined): Promise<PrivateKey> {
    if (useDH) {
        switch (useDH) {
            case 'x25519':
                return (await new X25519Algorithm().generate()).private;
            case 'p256':
                return (await new ECCDHSpecificAlgorithm(CURVES['P-256']).generate()).private;
            default:
                throw new Error(`unknown: ${useDH}`);
        }
    } else {
        return (await new Ed25519Algorithm().generate()).private;
    }
}

describe('communication tests', () => {
    for (const testCase of testCases) {
        it(testCase.name, async () => {
            const serverStaticKey = testCase.serverUseSignature ? await generateSignatureKey(testCase.serverUseDHSignature) : null
            const clientStaticKey = testCase.clientUseSignature ? await generateSignatureKey(testCase.clientUseDHSignature) : null
            const server = new Session(false, serverStaticKey);
            const client = new Session(true, clientStaticKey);

            (client as any).localState = new TestSymmetricState('client-local');
            (client as any).remoteState = new TestSymmetricState('client-remote');
            (server as any).localState = new TestSymmetricState('server-local');
            (server as any).remoteState = new TestSymmetricState('server-remote');

            client.send = (payload) => {
                setTimeout(() => server.handleReceive(payload), 0);
            };
            server.send = (payload) => {
                setTimeout(() => client.handleReceive(payload), 0);
            };

            const [clientResult, serverResult] = await Promise.all([
                client.handshake(testCase.clientAdditional),
                server.handshake(testCase.serverAdditional),
            ]);

            const clientStateA = (client as any).localState as TestSymmetricState;
            const clientStateB = (server as any).remoteState as TestSymmetricState;
            expect(clientStateA.recordedKeys).toEqual(clientStateB.recordedKeys);

            if (testCase.serverAdditional) {
                expect(clientResult.peerAdditionalData).toBeInstanceOf(Uint8Array)
                expect(clientResult.peerAdditionalData).toBytesEqual(testCase.serverAdditional);
            }
            if (testCase.clientAdditional) {
                expect(serverResult.peerAdditionalData).toBeInstanceOf(Uint8Array)
                expect(serverResult.peerAdditionalData).toBytesEqual(testCase.clientAdditional);
            }

            if (serverStaticKey) {
                expect(clientResult.remotePublicKey?.marshalToProto()).toStrictEqual(serverStaticKey.getPublic().marshalToProto())
            }
            if (clientStaticKey) {
                expect(serverResult.remotePublicKey?.marshalToProto()).toStrictEqual(clientStaticKey.getPublic().marshalToProto())
            }

            const serverCh = new Channel<Uint8Array>();
            server.onReceive = (data) => {
                serverCh.send(data);
            };
            const clientCh = new Channel<Uint8Array>();
            client.onReceive = (data) => {
                clientCh.send(data);
            };

            for (let i = 0; i < 10; i++) {
                let buf = crypto.randomBytes(1024);
                server.write(buf);
                let recv = await clientCh.receive();
                expect(recv).toBytesEqual(buf);

                buf = crypto.randomBytes(1024);
                client.write(buf);
                recv = await serverCh.receive();
                expect(recv).toBytesEqual(buf);
            }
        }, 700);
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

class TestSymmetricState extends SymmetricState {
    constructor(public readonly name: string) {
        super();
    }

    public recordedKeys: Bytes[] = [];

    mixKey(cipher: CipherAlgorithm, key: Bytes) {
        this.recordedKeys.push(key);
        super.mixKey(cipher, key);
    }
}