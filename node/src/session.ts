import * as proto from './proto';
import {
    Bytes,
    DHPublicKey,
    SignatureKeyPair,
    SignaturePublicKey,
    DHKeyPair,
    getSignatureAlgorithm,
    getDHAlgorithm,
    getCipherAlgorithm,
} from './crypto';
import { SymmetricState } from './symmetricstate';
const EMPTY = new Uint8Array(0);

function encodeUint32(n: number): Bytes {
    const buf = new Uint8Array(4);
    buf[0] = n & 0xff;
    buf[1] = (n >> 8) & 0xff;
    buf[2] = (n >> 16) & 0xff;
    buf[3] = (n >> 24) & 0xff;
    return buf;
}

export interface HandshakeResult {
    remotePublicKey?: SignaturePublicKey;
    peerAdditionalData?: Uint8Array;
}

export class Session {
    public send!: (payload: proto.Payload) => void;

    private handshakePromise: ((err: Error | null) => void) | null = null;
    private localState = new SymmetricState();
    private remoteState = new SymmetricState();

    private ephemeralKeyPair: DHKeyPair | null = null;
    private remoteEphemeralPublicKey: DHPublicKey | null = null;

    private availableEphemeralKeyAlgorithms: proto.DHAlgorithm[] = [
        proto.DHAlgorithm.DHX25519,
    ];
    private availableCipherAlgorithms: proto.CipherAlgorithm[] = [
        proto.CipherAlgorithm.CipherAesGcm,
    ];

    private remotePublicKey: SignaturePublicKey | null = null;
    private handshakeResult: HandshakeResult = {};
    private handshakeAdditionalData: Uint8Array | null = null;

    constructor(
        public readonly initiator: boolean,
        public readonly signatureKeyPair?: SignatureKeyPair | null,
    ) {

    }

    handshake(additional: Uint8Array | null): Promise<HandshakeResult> {
        this.handshakeAdditionalData = additional;
        return new Promise<HandshakeResult>((resolve, reject) => {
            this.handshakePromise = (err) => {
                if (err) {
                    reject(err);
                } else {
                    if (this.remotePublicKey) {
                        this.handshakeResult.remotePublicKey = this.remotePublicKey;
                    }
                    resolve(this.handshakeResult);
                }
            }
            if (this.initiator) {
                this.sendHello(false);
            }
        });
    }

    public handleReceive(payload: proto.Payload) {
        switch (payload.payloadType) {
            case proto.PayloadType.PayloadHello:
                return this.handleHello(payload.data, false);
            case proto.PayloadType.PayloadHelloWithChangeAlgorithm:
                return this.handleHello(payload.data, true);
        }
    }

    private async handleHello(payload: Bytes, retry: boolean) {
        try {
            let handshakeFinish: boolean = false;

            let sendRetry: boolean = false;

            const hello = proto.Hello.decode(payload);
            const helloSigned = hello.signed!;
            const helloBytes = proto.HelloBytes.decode(payload);
            const helloSignedBytes = proto.HelloSignedBytes.decode(helloBytes.signed);

            if (helloSigned.publicKey) {
                const signatureAlgorithm = getSignatureAlgorithm(helloSigned.publicKey.algorithm);
                const publicKey = signatureAlgorithm.unmarshalPublicKey(helloSigned.publicKey.data);
                const verified = await publicKey.verify(helloBytes.signed, helloBytes.signature);
                if (!verified) {
                    throw new Error('payload verification failed');
                }
                this.remotePublicKey = publicKey;
            }

            if (this.availableCipherAlgorithms.findIndex(v => v === helloSigned.cipherAlgorithm) < 0) {
                if (retry) {
                    throw new Error('any cipher not supported');
                }

                this.availableCipherAlgorithms = this.availableCipherAlgorithms.filter(v => helloSigned.supportCipher.findIndex(t => t === v) >= 0);
                if (this.availableCipherAlgorithms.length === 0) {
                    throw new Error('any cipher not supported');
                }

                sendRetry = true
            }
            if (this.availableEphemeralKeyAlgorithms.findIndex(v => v === helloSigned.ephemeralKey!.algorithm) < 0) {
                if (retry) {
                    throw new Error('any dh not supported');
                }

                this.availableEphemeralKeyAlgorithms = this.availableEphemeralKeyAlgorithms.filter(v => helloSigned.supportDh.findIndex(t => t === v) >= 0);
                if (this.availableCipherAlgorithms.length === 0) {
                    throw new Error('any dh not supported');
                }

                sendRetry = true;
            }

            if (retry || sendRetry) {
                this.handshakeResult = {};
                this.localState = new SymmetricState();
                this.remoteState = new SymmetricState();
                this.ephemeralKeyPair = null;
                if (sendRetry) {
                    await this.sendHello(true);
                    return
                }
            }

            this.remoteState.mixHash(encodeUint32(hello.version)); // hello_01
            if (helloSigned.publicKey) {
                this.remoteState.mixHash(helloSignedBytes.publicKey); // hello_02
            }
            const dhAlgorithm = getDHAlgorithm(helloSigned.ephemeralKey!.algorithm);
            this.remoteEphemeralPublicKey = dhAlgorithm.unmarshalPublicKey(helloSigned.ephemeralKey!.data);

            if (this.ephemeralKeyPair) {
                const cipherAlgorithm = getCipherAlgorithm(helloSigned.cipherAlgorithm);
                const sharedKey = this.ephemeralKeyPair.private.dh(this.remoteEphemeralPublicKey);
                this.remoteState.mixKey(cipherAlgorithm, sharedKey); // hello_03
                handshakeFinish = true;
            } else {
                this.remoteState.mixHash(helloSignedBytes.ephemeralKey); // hello_03
            }
            if (helloSigned.additional.length > 0) {
                this.handshakeResult.peerAdditionalData = this.remoteState.mixHashAndDecrypt(helloSigned.additional) // hello_04
            }

            if (helloBytes.signature.length > 0) {
                this.remoteState.mixHash(helloBytes.signature); // hello_05
            }

            if (handshakeFinish) {
                if (this.handshakePromise) {
                    this.handshakePromise(null);
                } else {
                    // illegal state
                }
            } else {
                console.log(`SESSION[init=${this.initiator}] SEND HELLO`);
                await this.sendHello(sendRetry);
            }
        } catch (e: any) {
            if (this.handshakePromise) {
                this.handshakePromise(e);
                this.handshakePromise = null;
            }
        }
    }

    private async sendHello(changeAlgorithm: boolean) {
        let handshakeFinish: boolean = false;

        const dhAlgorithm = getDHAlgorithm(this.availableEphemeralKeyAlgorithms[0]);
        const cipherAlgorithm = getCipherAlgorithm(this.availableCipherAlgorithms[0]);

        const hello: proto.HelloBytes = {
            version: 1,
            signed: EMPTY,
            signature: EMPTY,
        };
        this.localState.mixHash(encodeUint32(hello.version)); // hello_01

        const helloSigned: proto.HelloSignedBytes = {
            supportDh: [
                proto.DHAlgorithm.DHX25519
            ],
            supportCipher: [
                proto.CipherAlgorithm.CipherAesGcm,
            ],
            cipherAlgorithm: cipherAlgorithm.type,
            publicKey: EMPTY,
            ephemeralKey: EMPTY,
            additional: this.handshakeAdditionalData || EMPTY,
        };
        const publicKeyProto = this.signatureKeyPair?.public?.marshalToProto();
        if (publicKeyProto) {
            helloSigned.publicKey = proto.SignaturePublicKey.encode(publicKeyProto).finish();
            this.localState.mixHash(helloSigned.publicKey); // hello_02
        }

        if (!this.ephemeralKeyPair) {
            this.ephemeralKeyPair = dhAlgorithm.generate();
        }
        const ephemeralPublicKey: proto.DHPublicKey = {
            algorithm: dhAlgorithm.type,
            data: this.ephemeralKeyPair.public.marshal(),
        }
        helloSigned.ephemeralKey = proto.DHPublicKey.encode(ephemeralPublicKey).finish();

        if (this.remoteEphemeralPublicKey) {
            const sharedKey = this.ephemeralKeyPair.private.dh(this.remoteEphemeralPublicKey);
            this.localState.mixKey(cipherAlgorithm, sharedKey); // hello_03
            handshakeFinish = true;
        } else {
            this.localState.mixHash(helloSigned.ephemeralKey); // hello_03
        }

            if (this.handshakeAdditionalData && this.handshakeAdditionalData.length > 0) {
            helloSigned.additional = this.localState.encryptAndMixHash(this.handshakeAdditionalData, false); // hello_04
        }

        hello.signed = proto.HelloSignedBytes.encode(helloSigned).finish();
        if (this.signatureKeyPair) {
            hello.signature = await this.signatureKeyPair.private.sign(hello.signed);
            this.localState.mixHash(hello.signature); // hello_05
        }

        if (handshakeFinish) {
            if (this.handshakePromise) {
                this.handshakePromise(null);
            } else {
                throw new Error('illegal state');
            }
            this.handshakePromise = null;
        }

        const payload: proto.Payload = {
            payloadType: changeAlgorithm ? proto.PayloadType.PayloadHelloWithChangeAlgorithm : proto.PayloadType.PayloadHello,
            data: proto.HelloBytes.encode(hello).finish(),
        };
        this.send(payload);
    }
}