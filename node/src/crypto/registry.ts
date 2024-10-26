import * as proto from '../proto';
import { Cipher, DHAlgorithm, SignatureAlgorithm } from './types';
import { AesGcmCipher } from './aes';
import { Ed25519Algorithm } from './ed25519';
import { X509SignatureAlgorithm } from './x509';
import { X25519Algorithm } from './dh';

export function getCipherAlgorithm(type: proto.CipherAlgorithm): Cipher {
    switch (type) {
        case proto.CipherAlgorithm.CipherAesGcm:
            return new AesGcmCipher();

        default:
            throw new Error(`unknown cipher algorithm: ${type}`);
    }
}

export function getSignatureAlgorithm(type: proto.SignatureAlgorithm): SignatureAlgorithm {
    switch (type) {
        case proto.SignatureAlgorithm.SignatureEd25519:
            return new Ed25519Algorithm();
        case proto.SignatureAlgorithm.SignatureX509:
            return new X509SignatureAlgorithm();
        default:
            throw new Error(`unknown signature algorithm: ${type}`);
    }
}

export function getDHAlgorithm(type: proto.DHAlgorithm): DHAlgorithm {
    switch (type) {
        case proto.DHAlgorithm.DHX25519:
            return new X25519Algorithm();

        default:
            throw new Error(`unknown key type: ${type}`);
    }
}
