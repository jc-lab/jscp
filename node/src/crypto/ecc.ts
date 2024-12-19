import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import { Buffer } from 'buffer';
import {
    PublicAlgorithm,
    DHAlgorithm,
    PublicKey,
    DHPublicKey,
    DHKeyPair,
    DHPrivateKey,
    SignaturePublicKey,
    SignaturePrivateKey,
} from './types';
import * as proto from '../proto';

import { type CurveFn } from '@noble/curves/abstract/weierstrass';

import { p256 } from '@noble/curves/p256';
import { p384 } from '@noble/curves/p384';
import { p521 } from '@noble/curves/p521';

export type CurveDefine = {
    oid: string;
} & CurveFn

export const CURVES: Record<string, CurveDefine> = {
    'P-256': {
        oid: '1.2.840.10045.3.1.7',
        ...p256,
    },
    'P-384': {
        oid: '1.3.132.0.34',
        ...p384,
    },
    'P-521': {
        oid: '1.3.132.0.35',
        ...p521,
    },
};

export enum KeyUsage {
    DH = 1,
    Signature = 2,
}

export interface SubjectPublicKeyInfo {
    algorithm: {
        algorithm: string;
        parameters: ArrayBuffer;
    };
    publicKey: ArrayBuffer;
}

export class ECCAlgorithm implements PublicAlgorithm {
    protected keyUsage: KeyUsage;

    constructor(keyUsage: KeyUsage) {
        this.keyUsage = keyUsage;
    }

    // PublicAlgorithm

    getKeyFormat(): proto.KeyFormat {
        return proto.KeyFormat.KeyFormatSubjectPublicKeyInfo;
    }

    async unmarshalPublicKey(input: Uint8Array): Promise<PublicKey> {
        return ECCAlgorithm.unmarshalPublicKeyImpl(this.keyUsage, input);
    }

    static async unmarshalPublicKeyImpl(keyUsage: KeyUsage, input: Uint8Array): Promise<ECCPublicKey> {
        const publicKeyInfo = pkijs.PublicKeyInfo.fromBER(input);
        if (publicKeyInfo.algorithm.algorithmId !== '1.2.840.10045.2.1') {
            throw new Error(`unknown public key: ${publicKeyInfo.algorithm.algorithmId}`);
        }
        const algorithmParams = publicKeyInfo.algorithm.algorithmParams;
        if (!(algorithmParams instanceof asn1js.ObjectIdentifier)) {
            throw new Error(`unknown public key: ${publicKeyInfo.algorithm}`);
        }
        const algorithmOid = algorithmParams.getValue();
        const curve = Object.values(CURVES).find(v => v.oid === algorithmOid);
        if (!curve) {
            throw new Error(`unknown curve: ${algorithmOid}`);
        }
        const keyRaw = publicKeyInfo.subjectPublicKey.valueBlock.valueHexView;
        return new ECCPublicKey(keyUsage, curve, keyRaw);
    }
}

export class ECCDHSpecificAlgorithm extends ECCAlgorithm implements DHAlgorithm {
    constructor(
        public readonly curve: CurveDefine
    ) {
        super(KeyUsage.DH);
    }

    // DHAlgorithm

    getType(): proto.DHAlgorithm {
        return proto.DHAlgorithm.DHECC;
    }

    async generate(): Promise<DHKeyPair> {
        const privateKey = this.curve.utils.randomPrivateKey();
        const publicKey = this.curve.getPublicKey(privateKey);
        return {
            private: new ECCPrivateKey(this.keyUsage, this.curve, privateKey),
            public: new ECCPublicKey(this.keyUsage, this.curve, publicKey),
        };
    }

    async unmarshalDHPublicKey(input: Uint8Array): Promise<DHPublicKey> {
        return ECCAlgorithm.unmarshalPublicKeyImpl(KeyUsage.DH, input)
    }
}

export class ECCPublicKey implements DHPublicKey, SignaturePublicKey {
    constructor(
        public readonly keyUsage: KeyUsage,
        public readonly curve: CurveDefine,
        public readonly key: Uint8Array,
    ) {
    }

    isDHKey(): boolean {
        return this.keyUsage === KeyUsage.DH;
    }

    isSignatureKey(): boolean {
        return this.keyUsage === KeyUsage.Signature;
    }

    algorithm(): PublicAlgorithm {
        return this.getAlgorithmImpl();
    }

    async verify(data: Uint8Array, signature: Uint8Array): Promise<boolean> {
        return this.curve.verify(signature, data, this.key, { prehash: true })
    }

    getDHAlgorithm(): DHAlgorithm {
        return this.getAlgorithmImpl();
    }

    getDHAlgorithmProto(): proto.DHAlgorithm {
        return proto.DHAlgorithm.DHECC;
    }

    marshal(): Uint8Array {
        const publicKeyInfo = new pkijs.PublicKeyInfo({
            algorithm: new pkijs.AlgorithmIdentifier({
                algorithmId: '1.2.840.10045.2.1',
                algorithmParams: new asn1js.ObjectIdentifier({
                    value: this.curve.oid,
                })
            }),
            subjectPublicKey: new asn1js.BitString({
                valueHex: this.key,
            })
        })
        return Buffer.from(publicKeyInfo.toString('base64'), 'base64');
    }

    marshalToProto(): proto.PublicKey {
        return {
            format: proto.KeyFormat.KeyFormatSubjectPublicKeyInfo,
            data: this.marshal(),
        };
    }

    getAlgorithmImpl(): ECCDHSpecificAlgorithm {
        return new ECCDHSpecificAlgorithm(this.curve);
    }
}

export class ECCPrivateKey implements DHPrivateKey, SignaturePrivateKey {
    constructor(
        public readonly keyUsage: KeyUsage,
        public readonly curve: CurveDefine,
        public readonly key: Uint8Array,
    ) {}

    isDHKey(): boolean {
        return this.keyUsage === KeyUsage.DH;
    }

    isSignatureKey(): boolean {
        return this.keyUsage === KeyUsage.Signature;
    }

    algorithm(): PublicAlgorithm {
        return this.getAlgorithmImpl();
    }

    toPublic(): ECCPublicKey {
        return new ECCPublicKey(this.keyUsage, this.curve, this.curve.getPublicKey(this.key, true));
    }

    getPublic(): PublicKey {
        return this.toPublic();
    }

    getDHPublic(): DHPublicKey {
        return this.toPublic();
    }

    getSignaturePublicKey(): SignaturePublicKey {
        return this.toPublic();
    }

    async sign(data: Uint8Array): Promise<Uint8Array> {
        return this.curve.sign(data, this.key, { prehash: true }).toDERRawBytes(true);
    }

    getDHAlgorithm(): DHAlgorithm {
        return this.getAlgorithmImpl();
    }

    getDHAlgorithmProto(): proto.DHAlgorithm {
        return proto.DHAlgorithm.DHECC;
    }

    async dh(peerKey: DHPublicKey): Promise<Uint8Array> {
        if (!(peerKey instanceof ECCPublicKey)) {
            throw new Error('peerKey is not ECCDH');
        }
        return this.curve.getSharedSecret(this.key, peerKey.key, true);
    }

    getAlgorithmImpl(): ECCDHSpecificAlgorithm {
        return new ECCDHSpecificAlgorithm(this.curve);
    }
}
