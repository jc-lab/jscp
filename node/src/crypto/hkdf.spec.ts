import * as hex from '@stablelib/hex';
import { hkdf } from './hkdf';

describe('hkdf', () => {
    it('test vector', () => {
        const key = hex.decode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        const salt = hex.decode('000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F');
        const expected1 = hex.decode('c123697db89a6178c4c82fc7109c04b092253f1194aac2ea0bbf0becfd9cf014');
        const expected2 = hex.decode('dc9b865ddb0ad537996a627e72c966bb5439cfa142dffe3f0b2aa8969eb58672');

        const [ got1, got2 ] = hkdf(key, salt);

        expect(got1).toBytesEqual(expected1);
        expect(got2).toBytesEqual(expected2);
    });
});