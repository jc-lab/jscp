import { Bytes } from './types';
import * as proto from '../proto';

import * as x25519 from '@stablelib/x25519';

export interface SignatureAlgorithm {
    readonly type: proto.SignatureAlgorithm;
}

export interface SignaturePrivateKey {
    readonly algorithm: SignatureAlgorithm;
    sign: (data: Bytes) => Promise<Bytes>;
}

export interface SignaturePublicKey {
    readonly algorithm: SignatureAlgorithm;
    verify: (data: Bytes, signature: Bytes) => Promise<Bytes>;
}


export function unmarshalSignaturePublicKey(input: proto.SignaturePublicKey): SignaturePublicKey {

}