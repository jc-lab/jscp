import { HKDF } from '@stablelib/hkdf';
import { Bytes } from './types';
import { SHA256 } from '@stablelib/sha256';

export function hkdf(
    key: Bytes /* ikm */,
    salt?: Bytes /* old key */
): [Bytes, Bytes] {
    const hkdf = new HKDF(SHA256, key, salt);
    const okm = hkdf.expand(96);

    const k1 = okm.subarray(0, 32);
    const k2 = okm.subarray(32, 64);

    return [k1, k2];
}
