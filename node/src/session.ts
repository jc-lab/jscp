import * as proto from './proto';
import {
    Bytes,
    DHPrivateKey,
    DHPublicKey,
    Cipher,
    Nonce,
    SignatureKeyPair,
    SignaturePublicKey,
    getSignatureAlgorithm,
    getDHAlgorithm,
    getCipherAlgorithm,
    hkdf, DHKeyPair,
} from './crypto';
import { hash } from '@stablelib/sha256';
import { concat } from 'uint8arrays/concat';

const EMPTY = new Uint8Array(0);

function encodeUint32(n: number): Bytes {
    const buf = new Uint8Array(4);
    buf[0] = n & 0xff;
    buf[1] = (n >> 8) & 0xff;
    buf[2] = (n >> 16) & 0xff;
    buf[3] = (n >> 24) & 0xff;
    return buf;
}

class CipherState {
    public readonly nonce: Nonce;

    constructor(
        public readonly cipher: Cipher,
        public readonly key: Bytes,
    ) {
        this.nonce = new Nonce(12);
    }
}

class SymmetricState {
    public ck: Bytes = EMPTY;
    public h: Bytes = EMPTY;
    public cs: CipherState | null = null;

    public hasKey(): boolean {
        return !!this.cs;
    }
    
    public mixHash(data: Bytes) {
        this.h = hash(concat([this.h, data]));
    }

    public mixKey(cipher: Cipher, key: Bytes) {
        const [ck, temp] = hkdf(key, this.ck);
        this.ck = ck;
        this.cs = new CipherState(cipher, temp);
    }

    public encryptAndMixHash(plaintext: Bytes, mustSecret: boolean): Bytes {
        let ciphertext: Uint8Array;
        if (this.cs) {
            ciphertext = this.cs.cipher.seal(this.cs.key, this.cs.nonce.getBytes(), plaintext, this.h);
            this.cs.nonce.increment();
        } else {
            if (mustSecret) {
                throw new Error('must secret');
            }
            ciphertext = plaintext;
        }
        this.mixHash(ciphertext);
        return ciphertext;
    }

    // throwable
    public mixHashAndDecrypt(ciphertext: Bytes): Bytes {
        this.mixHash(ciphertext);
        if (this.cs) {
            const plaintext = this.cs.cipher.open(this.cs.key, this.cs.nonce.getBytes(), ciphertext, this.h);
            this.cs.nonce.increment();
            return plaintext;
        } else {
            return ciphertext;
        }
    }
}

export class Session {
    public forceFailForTest: boolean = false;

    public send!: (payload: proto.Payload) => void;

    private handshakePromise: ((err: Error | null) => void) | null = null;
    private localState = new SymmetricState();
    private remoteState = new SymmetricState();

    private ephemeralKeyPair: DHKeyPair | null = null;
    private remoteEphemeralPublicKey: DHPublicKey | null = null;
    private remotePublicKey: SignaturePublicKey | null = null;

    private availableEphemeralKeyAlgorithms: proto.DHAlgorithm[] = [
        proto.DHAlgorithm.DHX25519,
    ];
    private availableCipherAlgorithms: proto.CipherAlgorithm[] = [
        proto.CipherAlgorithm.CipherAesGcm,
    ];

    constructor(
        public readonly initiator: boolean,
        public readonly signatureKeyPair?: SignatureKeyPair | null,
        public readonly additional?: Bytes | null,
    ) {

    }

    handshake(): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            this.handshakePromise = (err) => {
                if (err) {
                    reject(err);
                } else {
                    resolve();
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

            if (this.forceFailForTest) {
                this.forceFailForTest = false;
                sendRetry = true;
            }

            if (retry || sendRetry) {
                this.localState = new SymmetricState();
                this.remoteState = new SymmetricState();
                this.ephemeralKeyPair = null;
            }

            if (helloSigned.publicKey) {
                const signatureAlgorithm = getSignatureAlgorithm(helloSigned.publicKey.algorithm);
                const publicKey = signatureAlgorithm.unmarshalPublicKey(helloSigned.publicKey.data);
                const verified = await publicKey.verify(helloBytes.signed, helloBytes.signature);
                if (!verified) {
                    throw new Error('payload verification failed');
                }
                this.remotePublicKey = publicKey;
            }

            this.remoteState.mixHash(encodeUint32(hello.version)); // hello_01
            if (helloSigned.publicKey) {
                this.remoteState.mixHash(helloSignedBytes.publicKey); // hello_02
            }
            const dhAlgorithm = getDHAlgorithm(helloSigned.ephemeralKey!.algorithm);
            this.remoteEphemeralPublicKey = dhAlgorithm.unmarshalPublicKey(helloSigned.ephemeralKey!.data);

            this.remoteState.mixHash(helloSignedBytes.ephemeralKey); // hello_03
            if (this.ephemeralKeyPair) {
                handshakeFinish = true;
            }
            if (helloSigned.additional.length > 0) {
                this.remoteState.mixHashAndDecrypt(helloSigned.additional) // hello_04
            }

            if (helloBytes.signature.length > 0) {
                this.remoteState.mixHash(helloBytes.signature); // hello_05
            }

            if (handshakeFinish) {
                this.handshakePromise!(null);
                this.handshakePromise = null;
            } else {
                this.sendHello(sendRetry);
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
            additional: this.additional || EMPTY,
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

        if (this.additional && this.additional.length > 0) {
            helloSigned.additional = this.localState.encryptAndMixHash(this.additional, false); // hello_04
        }

        hello.signed = proto.HelloSignedBytes.encode(helloSigned).finish();
        if (this.signatureKeyPair) {
            hello.signature = await this.signatureKeyPair.private.sign(hello.signed);
            this.localState.mixHash(hello.signature); // hello_05
        }

        if (handshakeFinish) {
            this.handshakePromise!(null);
            this.handshakePromise = null;
        }

        const payload: proto.Payload = {
            payloadType: changeAlgorithm ? proto.PayloadType.PayloadHelloWithChangeAlgorithm : proto.PayloadType.PayloadHello,
            data: proto.HelloBytes.encode(hello).finish(),
        };
        this.send(payload);
    }
}