import { Hash } from '@stablelib/hash';
import { Bytes } from './types';

export type HashConstructor = new () => Hash;

export function hash(hashClass: HashConstructor, data: Bytes): Bytes {
    const h = new hashClass();
    h.update(data);
    const digest = h.digest();
    h.clean();
    return digest;
}
