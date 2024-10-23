import { HashConstructor } from './hash';
import { HKDF } from '@stablelib/hkdf';
import { Bytes } from './types';

export function hkdf(
    hashClass: HashConstructor,
    key: Bytes /* ikm */,
    salt: Bytes /* old key */
): [Bytes, Bytes] {
    const hkdf = new HKDF(hashClass, key, salt);
    const okm = hkdf.expand(96);

    const k1 = okm.subarray(0, 32);
    const k2 = okm.subarray(32, 64);

    return [k1, k2];
}
