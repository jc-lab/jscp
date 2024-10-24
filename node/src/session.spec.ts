import { Session } from './session';

describe('communication tests', () => {
    for (let i=0; i<2; i++) {
        it(`no static - no static - ${(i===0) ? 'without additional' : 'with additional'}`, async () => {
            const server = new Session(false, null, (i === 0) ? null : Buffer.from('i am server'));
            const client = new Session(true, null, (i === 0) ? null : Buffer.from('i am client'));

            client.send = (payload) => {
                setTimeout(() => server.handleReceive(payload), 0);
            };
            server.send = (payload) => {
                setTimeout(() => client.handleReceive(payload), 0);
            };

            const a = client.handshake();
            const b = server.handshake();

            await Promise.all([a, b]);
        }, 500);
    }
})


describe('communication tests change algorithm', () => {
    for (let i=0; i<2; i++) {
        it(`no static - no static - ${(i===0) ? 'without additional' : 'with additional'}`, async () => {
            const server = new Session(false, null, (i === 0) ? null : Buffer.from('i am server'));
            const client = new Session(true, null, (i === 0) ? null : Buffer.from('i am client'));

            server.forceFailForTest = true;

            client.send = (payload) => {
                console.log(`CLIENT SEND: ${payload.payloadType}`);
                setTimeout(() => server.handleReceive(payload), 0);
            };
            server.send = (payload) => {
                console.log(`SERVER SEND: ${payload.payloadType}`);
                setTimeout(() => client.handleReceive(payload), 0);
            };

            const a = client.handshake();
            const b = server.handshake();

            await Promise.all([a, b]);
        }, 500);
    }
})