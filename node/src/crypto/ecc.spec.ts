import { CURVES, ECCAlgorithm, ECCDHSpecificAlgorithm, ECCPrivateKey, ECCPublicKey, KeyUsage } from './ecc';
import { Buffer } from 'buffer';

// Test vectors for P-256
const P256_PRIVATE_KEY_1 = 'suSa+hGh504sr8nsJ2Y5XksRx+5BbpFjIWTkrrcNHIU='; // raw base64
const P256_PUBLIC_KEY_1  = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJxEwCKOTITrXN67yS57pQhkmUhDmiZlU5m2d3H/6iTSq8OLzTw0ciVK3OmjkkHFZEYTqUdXwjzN94sPRpl/hxg=='; // DER base64
const P256_PRIVATE_KEY_2 = 'oDi1R7Q84lCsVC+iwfVeH3bsxUnml1JRMVLDuQEcMKg='; // raw base64
const P256_PUBLIC_KEY_2  = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENb5eHL/zl/FKxIKsmb3aicwCwJdDMB07jwvM7kt9G9V8BHxIKd1J/Pg1La8n09Iry84z7tpXIkJ8zT0FD12fkQ=='; // DER base64

// // Test vectors for P-384
// const P384_PRIVATE_KEY_1 = '37knmBrpyWHTAXXJYvyfgH64TuXp7nxgyGRpeBUucUSzWPkanXlsMhtS6Ywo3/Ec'; // raw base64
// const P384_PUBLIC_KEY_1  = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENb5eHL/zl/FKxIKsmb3aicwCwJdDMB07jwvM7kt9G9V8BHxIKd1J/Pg1La8n09Iry84z7tpXIkJ8zT0FD12fkQ=='; // raw base64
// const P384_PRIVATE_KEY_2 = '/G/0A1QeRaFcxVjODRm1PfsF0uOQE4mAfNWoxxqGwfPwn+FdiyLFEKVk3VIwBccv'; // DER base64
// const P384_PUBLIC_KEY_2  = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENb5eHL/zl/FKxIKsmb3aicwCwJdDMB07jwvM7kt9G9V8BHxIKd1J/Pg1La8n09Iry84z7tpXIkJ8zT0FD12fkQ=='; // DER base64
//
// // Test vectors for P-521
// const P521_PRIVATE_KEY_1 = 'AZ25uFEm3281OHDQC5vNgfIZCzGX5anhtdfTapiEpqYAoEB+X4+FsheE+iCPrr7UY5wSrt05oaGhpJ5S/w/pFpKc'; // raw base64
// const P521_PUBLIC_KEY_1  = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENb5eHL/zl/FKxIKsmb3aicwCwJdDMB07jwvM7kt9G9V8BHxIKd1J/Pg1La8n09Iry84z7tpXIkJ8zT0FD12fkQ=='; // raw base64
// const P521_PRIVATE_KEY_2 = 'AUO4IQDQ+RMWmkb+t2izeYyjIxTu3mIq/Ovb8usUT3152tlzm0muPqBK6MXEwQNgKy4cYydIGiLlzi3gBZhhYQGT'; // DER base64
// const P521_PUBLIC_KEY_2  = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENb5eHL/zl/FKxIKsmb3aicwCwJdDMB07jwvM7kt9G9V8BHxIKd1J/Pg1La8n09Iry84z7tpXIkJ8zT0FD12fkQ=='; // DER base64

describe('ECDH Key Exchange Tests', () => {
    const testCases = [
        {
            name: 'P-256',
            curve: CURVES['P-256'],
            privateKey1: P256_PRIVATE_KEY_1,
            privateKey2: P256_PRIVATE_KEY_2,
            publicKey1: P256_PUBLIC_KEY_1,
            publicKey2: P256_PUBLIC_KEY_2,
        },
        // {
        //     name: 'P-384',
        //     curve: CURVE_NAMES['P-384'],
        //     privateKey1: P384_PRIVATE_KEY_1,
        //     privateKey2: P384_PRIVATE_KEY_2,
        //     publicKey1: P384_PUBLIC_KEY_1,
        //     publicKey2: P384_PUBLIC_KEY_2,
        // },
        // {
        //     name: 'P-521',
        //     curve: CURVE_NAMES['P-521'],
        //     privateKey1: P521_PRIVATE_KEY_1,
        //     privateKey2: P521_PRIVATE_KEY_2,
        //     publicKey1: P521_PUBLIC_KEY_1,
        //     publicKey2: P521_PUBLIC_KEY_2,
        // },
    ];

    testCases.forEach(testCase => {
        describe(`${testCase.name} Tests`, () => {
            const ecdsaAlgorithm = new ECCAlgorithm(KeyUsage.Signature);

            let dhAlgorithm: ECCDHSpecificAlgorithm;
            let privateKey1Dh: ECCPrivateKey;
            let publicKey1Dh: ECCPublicKey;
            let privateKey2Dh: ECCPrivateKey;
            let publicKey2Dh: ECCPublicKey;
            let privateKey1: ECCPrivateKey;
            let publicKey1: ECCPublicKey;

            beforeAll(async () => {
                dhAlgorithm = new ECCDHSpecificAlgorithm(testCase.curve);

                // Create private keys
                privateKey1Dh = new ECCPrivateKey(
                    KeyUsage.DH,
                    testCase.curve,
                    Buffer.from(testCase.privateKey1, 'base64')
                );
                privateKey2Dh = new ECCPrivateKey(
                    KeyUsage.DH,
                    testCase.curve,
                    Buffer.from(testCase.privateKey2, 'base64')
                );

                // Unmarshal public keys
                const publicKeyData1 = Buffer.from(testCase.publicKey1, 'base64');
                const publicKeyData2 = Buffer.from(testCase.publicKey2, 'base64');
                publicKey1Dh = await dhAlgorithm.unmarshalDHPublicKey(publicKeyData1);
                publicKey2Dh = await dhAlgorithm.unmarshalDHPublicKey(publicKeyData2);

                privateKey1 = new ECCPrivateKey(
                    KeyUsage.Signature,
                    testCase.curve,
                    Buffer.from(testCase.privateKey1, 'base64')
                );
                publicKey1 = await ecdsaAlgorithm.unmarshalPublicKey(publicKeyData1);
            });

            test('Unmarshal public keys successfully', () => {
                expect(publicKey1Dh).toBeInstanceOf(ECCPublicKey);
                expect(publicKey2Dh).toBeInstanceOf(ECCPublicKey);
            });

            test('Public keys have correct curve', () => {
                expect(publicKey1Dh.curve.oid).toBe(testCase.curve.oid);
                expect(publicKey2Dh.curve.oid).toBe(testCase.curve.oid);
            });

            test('Public keys have correct usage', () => {
                expect(publicKey1Dh.keyUsage).toBe(KeyUsage.DH);
                expect(publicKey2Dh.keyUsage).toBe(KeyUsage.DH);
            });

            test('ECDH key exchange produces same shared secret', async () => {
                const sharedSecret1 = await privateKey1Dh.dh(publicKey2Dh);
                const sharedSecret2 = await privateKey2Dh.dh(publicKey1Dh);

                expect(Buffer.from(sharedSecret1).toString('hex'))
                    .toBe(Buffer.from(sharedSecret2).toString('hex'));
            });

            test('Marshal and unmarshal public key preserves data', async () => {
                const marshaledData1 = publicKey1Dh.marshalToProto();
                const unmarshaledKey1 = await dhAlgorithm.unmarshalDHPublicKey(marshaledData1.data);

                expect(Buffer.from(unmarshaledKey1.key).toString('hex'))
                    .toBe(Buffer.from(publicKey1Dh.key).toString('hex'));
            });

            test('Sign and verify with correct', async () => {
                const data = Buffer.from('hello world'.repeat(10));
                const signature = await privateKey1.sign(data);
                const result = await publicKey1.verify(data, signature);
                expect(result).toBeTruthy();
            });

            test('Sign and verify with incorrect', async () => {
                const data = Buffer.from('hello world'.repeat(10));
                const signature = await privateKey1.sign(data);
                const result = await publicKey1.verify(Buffer.from('hello world'.repeat(10) + 'a'), signature);
                expect(result).toBeFalsy();
            });
        });
    });
});
