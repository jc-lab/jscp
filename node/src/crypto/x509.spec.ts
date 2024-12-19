import * as cc from 'commons-crypto';
import { X509Pkcs8PrivateKey, X509SignatureAlgorithm } from './x509';

describe('x509 test', () => {
    const SAMPLE_P256_DER_CERT = Buffer.from(`MIIBiTCCAS+gAwIBAgIIFNZWRyPwNHgwCgYIKoZIzj0EAwIwDzENMAsGA1UEAxME
dGVzdDAeFw0yNDEwMjUwNjQ4MDBaFw0yNTEwMjUwNjQ4MDBaMA8xDTALBgNVBAMT
BHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQd1Z71D8wzhOfK9HiUosQc
Y0+oCxUfTrtlw+JXDdWORMNOdH78sybZ1bBk5bQIcUIVcNUSRs7ZaWyCSlHEPDSh
o3UwczAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTD72VybWvy77kP+low80oYVh5Y
aDALBgNVHQ8EBAMCA+gwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0RBAgwBoIE
dGVzdDARBglghkgBhvhCAQEEBAMCAPcwCgYIKoZIzj0EAwIDSAAwRQIhALAkWZYG
/WgCcBuObAM7ZEB3HXzZ8wo3UicGawTw7iJkAiBlFZwW1oaY42bPvd7x6zCo+k/5
2RFP0amS/TvpcSGczQ==`.replace(/\s/g, ''), 'base64');
    const SAMPLE_P256_PEM_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggJH9qg57sAllDJna
LvAHXUHP+KxYoMEr7NyvvpibPk6hRANCAAQd1Z71D8wzhOfK9HiUosQcY0+oCxUf
Trtlw+JXDdWORMNOdH78sybZ1bBk5bQIcUIVcNUSRs7ZaWyCSlHEPDSh
-----END PRIVATE KEY-----`;

    const x509Algorithm = new X509SignatureAlgorithm();

    it('sign and verify', async () => {
        const sampleP256PublicKey = await x509Algorithm.unmarshalPublicKey(SAMPLE_P256_DER_CERT);
        const sampleP256PrivateKey = new X509Pkcs8PrivateKey(sampleP256PublicKey, cc.createPrivateKey({
            format: 'pem',
            key: SAMPLE_P256_PEM_KEY,
        }));

        const data = Buffer.from('HELLO WORLD');
        const signature = await sampleP256PrivateKey.sign(data);
        expect(await sampleP256PublicKey.verify(data, signature)).toBeTruthy();
        expect(await sampleP256PublicKey.verify(Buffer.from('NOT HELLO'), signature)).toBeFalsy();
    });
});