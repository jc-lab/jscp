import * as proto from '../proto';
import { CipherAlgorithm, DHAlgorithm, PublicAlgorithm } from './types';
import { AesGcmCipher } from './aes';
import { ed25519Algorithm, Ed25519Algorithm } from './ed25519';
import { x509SignatureAlgorithm, X509SignatureAlgorithm } from './x509';
import { ECCAlgorithm, KeyUsage } from './ecc';
import { x25519Algorithm } from './x25519';

export function getCipherAlgorithm(type: proto.CipherAlgorithm): CipherAlgorithm {
    switch (type) {
        case proto.CipherAlgorithm.CipherAesGcm:
            return new AesGcmCipher();

        default:
            throw new Error(`unknown cipher algorithm: ${type}`);
    }
}

export function getPublicAlgorithm(keyFormat: proto.KeyFormat, isDHKey: boolean): PublicAlgorithm {
    switch (keyFormat) {
        case proto.KeyFormat.KeyFormatEd25519:
            return ed25519Algorithm;
        case proto.KeyFormat.KeyFormatX509Certificate:
            return x509SignatureAlgorithm;
        case proto.KeyFormat.KeyFormatX25519:
            return x25519Algorithm;
        case proto.KeyFormat.KeyFormatSubjectPublicKeyInfo:
            if (isDHKey) {
                return new ECCAlgorithm(KeyUsage.DH);
            } else {
                return new ECCAlgorithm(KeyUsage.Signature);
            }
        default:
            throw new Error(`unknown signature algorithm: ${keyFormat}`);
    }
}

export function getDHAlgorithm(type: proto.DHAlgorithm): DHAlgorithm {
    switch (type) {
        case proto.DHAlgorithm.DHX25519:
            return x25519Algorithm;

        default:
            throw new Error(`unknown key type: ${type}`);
    }
}
