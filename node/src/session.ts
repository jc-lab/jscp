import {
    Bytes,
    PublicKey,
    PrivateKey,
    DHPrivateKey,
    SignaturePrivateKey,
    DHPublicKey,
    DHAlgorithm,
    CipherAlgorithm,
    DHKeyPair,
    SignaturePublicKey,
} from './crypto/types';
import * as proto from './proto';
import { SymmetricState } from './symmetricstate';
import { getDHAlgorithm, getCipherAlgorithm, getPublicAlgorithm } from './crypto';

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
    remotePublicKey?: PublicKey;
    peerAdditionalData?: Bytes;
}

export class Session {
    public send: (payload: proto.Payload) => void;
    public onReceive: (data: Bytes) => void = () => {};

    private handshakePromise: ((err: Error | null) => void) | null = null;
    private localState = new SymmetricState();
    private remoteState = new SymmetricState();

    private dhAlgorithm: DHAlgorithm | null = null;
    private ephemeralKeyPair: DHKeyPair | null = null;
    private remoteEphemeralPublicKey: DHPublicKey | null = null;

    private availableEphemeralKeyAlgorithms: proto.DHAlgorithm[] = [
        proto.DHAlgorithm.DHX25519,
        proto.DHAlgorithm.DHECC,
    ];
    private availableCipherAlgorithms: proto.CipherAlgorithm[] = [
        proto.CipherAlgorithm.CipherAesGcm,
    ];

    private remotePublicKey: PublicKey | null = null;
    private handshakeResult: HandshakeResult = {};
    private handshakeAdditionalData: Bytes | null = null;

    constructor(
        public readonly initiator: boolean,
        public readonly staticKeyPair: PrivateKey | null = null,
    ) {
        if (staticKeyPair?.isDHKey()) {
            const dhKey = staticKeyPair as DHPrivateKey;
            this.availableEphemeralKeyAlgorithms = [dhKey.getDHAlgorithmProto()];
        }
    }

    private getDHAlgorithm(candidate: proto.DHAlgorithm): DHAlgorithm {
        if (this.dhAlgorithm) {
            return this.dhAlgorithm;
        }
        if (this.staticKeyPair?.isDHKey()) {
            const dhKey = this.staticKeyPair as DHPrivateKey;
            return dhKey.getDHAlgorithm();
        }
        return getDHAlgorithm(candidate);
    }

    public handshake(additional?: Bytes | null): Promise<HandshakeResult> {
        if (additional) {
            this.handshakeAdditionalData = additional;
        }
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
                this.sendHello(false).catch(err => {
                    if (this.handshakePromise) {
                        this.handshakePromise(err);
                    }
                });
            }
        });
    }

    public handleReceive(payload: proto.Payload): Promise<void> {
        switch (payload.payloadType) {
            case proto.PayloadType.PayloadHello:
                return this.handleHello(payload.data, false);
            case proto.PayloadType.PayloadHelloWithChangeAlgorithm:
                return this.handleHello(payload.data, true);
            case proto.PayloadType.PayloadEncryptedMessage:
                return this.handleEncryptedMessage(payload.data);
            default:
                return Promise.reject(new Error(`invalid payload type: ${payload.payloadType}`));
        }
    }

    public async write(data: Bytes): Promise<void> {
        const message = proto.EncryptedMessage.create({ data });
        const plaintext = proto.EncryptedMessage.encode(message).finish();
        const ciphertext = await this.localState.encryptWithAd(plaintext, EMPTY);

        const payload = proto.Payload.create({
            payloadType: proto.PayloadType.PayloadEncryptedMessage,
            data: ciphertext
        });
        this.send(payload);
    }

    private async handleHello(payload: Bytes, retry: boolean): Promise<void> {
        try {
            let handshakeFinish: boolean = false;
            let sendRetry: boolean = false;

            const hello = proto.Hello.decode(payload);
            const helloSigned = hello.signed!;
            const helloBytes = proto.HelloBytes.decode(payload);
            const helloSignedBytes = proto.HelloSignedBytes.decode(helloBytes.signed);

            // Check cipher algorithm compatibility
            if (!this.availableCipherAlgorithms.includes(helloSigned.cipherAlgorithm)) {
                if (retry) {
                    throw new Error('any cipher not supported');
                }

                this.availableCipherAlgorithms = this.availableCipherAlgorithms
                    .filter(algo => helloSigned.supportCipher.includes(algo));
                if (this.availableCipherAlgorithms.length === 0) {
                    throw new Error('any cipher not supported');
                }

                sendRetry = true;
            }

            let remotePublicKey: PublicKey | null = null;

            if (helloSigned.publicKey) {
                const publicKeyAlgorithm = getPublicAlgorithm(
                    helloSigned.publicKey.format,
                    helloSigned.dhAlsoPublicKey
                );
                remotePublicKey = await publicKeyAlgorithm.unmarshalPublicKey(helloSigned.publicKey.data);

                if (!helloSigned.dhAlsoPublicKey) {
                    const sigKey = remotePublicKey as SignaturePublicKey;
                    const verified = await sigKey.verify(helloBytes.signed, helloBytes.signature);
                    if (!verified) {
                        throw new Error('payload verification failed');
                    }
                    this.remotePublicKey = remotePublicKey;
                }
            }

            // Check DH algorithm compatibility
            if (!this.availableEphemeralKeyAlgorithms.includes(helloSigned.ephemeralKey!.algorithm)) {
                if (retry) {
                    throw new Error('any dh not supported');
                }

                this.availableEphemeralKeyAlgorithms = this.availableEphemeralKeyAlgorithms
                    .filter(algo => helloSigned.supportDh.includes(algo));
                if (this.availableEphemeralKeyAlgorithms.length === 0) {
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
                    return this.sendHello(true);
                }
            }

            this.remoteState.mixHash(encodeUint32(hello.version));

            const cipherAlgorithm = getCipherAlgorithm(helloSigned.cipherAlgorithm);

            let dhAlgorithm: DHAlgorithm | null = null;
            if (remotePublicKey != null) {
                if (helloSigned.dhAlsoPublicKey) {
                    const dhKey = remotePublicKey as DHPublicKey;
                    dhAlgorithm = dhKey.getDHAlgorithm();
                    if (this.ephemeralKeyPair) {
                        const sharedKey = await this.ephemeralKeyPair.private.dh(dhKey);
                        this.remoteState.mixKey(cipherAlgorithm, sharedKey); // hello_02
                        this.localState.mixKey(cipherAlgorithm, sharedKey); // hello_02
                    }
                } else {
                    this.remoteState.mixHash(helloSignedBytes.publicKey); // hello_02
                }
                this.remotePublicKey = remotePublicKey;
            }
            if (dhAlgorithm == null) {
                dhAlgorithm = this.getDHAlgorithm(helloSigned.ephemeralKey!.algorithm);
            }
            this.dhAlgorithm = dhAlgorithm;

            this.remoteEphemeralPublicKey = await dhAlgorithm.unmarshalDHPublicKey(helloSigned.ephemeralKey!.data);

            if (this.ephemeralKeyPair == null && helloSigned.additional.length > 0) {
                this.handshakeResult.peerAdditionalData = await this.remoteState.mixHashAndDecrypt(helloSigned.additional);
            }

            if (this.staticKeyPair?.isDHKey()) {
                const localDHKey = this.staticKeyPair as DHPrivateKey;
                const sharedKey = await localDHKey.dh(this.remoteEphemeralPublicKey);
                this.localState.mixKey(cipherAlgorithm, sharedKey); // hello_02
                this.remoteState.mixKey(cipherAlgorithm, sharedKey); // hello_02
            }

            if (this.ephemeralKeyPair) {
                const sharedKey = await this.ephemeralKeyPair.private.dh(this.remoteEphemeralPublicKey);
                this.localState.mixKey(cipherAlgorithm, sharedKey);
                this.remoteState.mixKey(cipherAlgorithm, sharedKey);
                handshakeFinish = true;
            } else {
                this.remoteState.mixHash(helloSignedBytes.ephemeralKey);
            }

            if (this.ephemeralKeyPair != null && helloSigned.additional.length > 0) {
                this.handshakeResult.peerAdditionalData = await this.remoteState.mixHashAndDecrypt(helloSigned.additional);
            }

            if (helloBytes.signature.length > 0) {
                this.remoteState.mixHash(helloBytes.signature);
            }

            if (handshakeFinish) {
                if (this.handshakePromise) {
                    this.handshakePromise(null);
                }
            } else {
                await this.sendHello(false);
            }
        } catch (e: any) {
            if (this.handshakePromise) {
                this.handshakePromise(e);
                this.handshakePromise = null;
            }
        }
    }

    private async handleEncryptedMessage(payload: Bytes): Promise<void> {
        const plaintext = await this.remoteState.decryptWithAd(payload, EMPTY);
        const message = proto.EncryptedMessage.decode(plaintext);
        this.onReceive(message.data);
    }

    private async sendHello(changeAlgorithm: boolean): Promise<void> {
        let handshakeFinish = false;

        const dhAlgorithm = this.getDHAlgorithm(this.availableEphemeralKeyAlgorithms[0]);
        const cipherAlgorithm = getCipherAlgorithm(this.availableCipherAlgorithms[0]);

        const hello: proto.HelloBytes = {
            version: 1,
            signed: EMPTY,
            signature: EMPTY,
        };
        this.localState.mixHash(encodeUint32(hello.version));

        const helloSigned: proto.HelloSignedBytes = {
            supportDh: this.availableEphemeralKeyAlgorithms,
            supportCipher: this.availableCipherAlgorithms,
            cipherAlgorithm: cipherAlgorithm.getType(),
            additional: this.handshakeAdditionalData || EMPTY,
            dhAlsoPublicKey: false,
            publicKey: EMPTY,
            ephemeralKey: null as any,
        };

        if (this.staticKeyPair) {
            const publicKeyProto = await this.staticKeyPair.getPublic().marshalToProto();
            const publicKeyBytes = proto.PublicKey.encode(publicKeyProto).finish();
            helloSigned.publicKey = publicKeyBytes;

            if (this.staticKeyPair.isSignatureKey()) {
                this.localState.mixHash(publicKeyBytes);
            } else if (this.staticKeyPair.isDHKey()) {
                helloSigned.dhAlsoPublicKey = true;
            }
        }

        if (!this.ephemeralKeyPair) {
            this.ephemeralKeyPair = await dhAlgorithm.generate();

            if (this.remotePublicKey?.isDHKey()) {
                const remoteKey = this.remotePublicKey as DHPublicKey;
                const shared = await this.ephemeralKeyPair.private.dh(remoteKey);
                this.localState.mixKey(cipherAlgorithm, shared); // hello_02
                this.remoteState.mixKey(cipherAlgorithm, shared); // hello_02
            }
        }

        const ephemeralPublicKey: proto.DHPublicKey = {
            algorithm: dhAlgorithm.getType(),
            data: this.ephemeralKeyPair.public.marshal(),
        };
        const ephemeralKeyBytes = proto.DHPublicKey.encode(ephemeralPublicKey).finish();
        helloSigned.ephemeralKey = ephemeralKeyBytes;

        if (this.remoteEphemeralPublicKey) {
            const sharedKey = await this.ephemeralKeyPair.private.dh(this.remoteEphemeralPublicKey);
            this.localState.mixKey(cipherAlgorithm, sharedKey);
            this.remoteState.mixKey(cipherAlgorithm, sharedKey);
            handshakeFinish = true;
        } else {
            this.localState.mixHash(ephemeralKeyBytes);
        }

        if (this.handshakeAdditionalData && this.handshakeAdditionalData?.length > 0) {
            helloSigned.additional = await this.localState.encryptAndMixHash(
                this.handshakeAdditionalData,
                false
            );
        }

        const signedBytes = proto.HelloSignedBytes.encode(helloSigned).finish();
        hello.signed = signedBytes;

        if (this.staticKeyPair?.isSignatureKey()) {
            const signatureKey = this.staticKeyPair as SignaturePrivateKey;
            hello.signature = await signatureKey.sign(hello.signed);
            this.localState.mixHash(hello.signature);
        }

        if (handshakeFinish) {
            if (this.handshakePromise) {
                this.handshakePromise(null);
            }
        }

        const payload: proto.Payload = {
            payloadType: changeAlgorithm
                ? proto.PayloadType.PayloadHelloWithChangeAlgorithm
                : proto.PayloadType.PayloadHello,
            data: proto.HelloBytes.encode(hello).finish(),
        };
        this.send(payload);
    }
}