import * as hex from '@stablelib/hex';
import { X25519Algorithm, X25519PrivateKey, X25519PublicKey } from './x25519';

const alice = {
    privateKey: hex.decode('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'),
    publicKey: hex.decode('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'),
}

const bob = {
    privateKey: hex.decode('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'),
    publicKey: hex.decode('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'),
}

const x25519 = new X25519Algorithm();

describe('X25519', () => {
    test('unmarshalDHPublicKey', async () => {
        const publicKey = await x25519.unmarshalPublicKey(alice.publicKey);
        expect(X25519PublicKey.checkInstance(publicKey)).toEqual(true);
        expect(publicKey.key).toBytesEqual(alice.publicKey);
    });

    test('dh', async () => {
        const alice2 = {
            private: new X25519PrivateKey(alice.privateKey),
            public: await x25519.unmarshalPublicKey(alice.publicKey),
        };
        const bob2 = {
            private: new X25519PrivateKey(bob.privateKey),
            public: await x25519.unmarshalPublicKey(bob.publicKey),
        };

        const s1 = await alice2.private.dh(bob2.public);
        const s2 = await bob2.private.dh(alice2.public);

        expect(s1).toStrictEqual(s2);
        expect(s1).toStrictEqual(hex.decode('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'));
    });
});
