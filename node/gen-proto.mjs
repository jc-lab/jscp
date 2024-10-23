import { fileURLToPath } from 'url';
import * as path from 'path';
import * as childProcess from 'child_process';

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const __filename = fileURLToPath(import.meta.url);

const exeExt = (process.platform === 'win32') ? '.exe' : '';
const protocGenTsName = `protoc-gen-ts_proto${exeExt}`;
const protocGenTsPath = process.env.BERRY_BIN_FOLDER ? path.join(process.env.BERRY_BIN_FOLDER, protocGenTsName) : path.join(__dirname, 'node_modules/.bin', protocGenTsName)

const protoDir = path.join(__dirname, '../java/src/main/proto');

const args = [
    `--plugin="protoc-gen-ts_proto=${protocGenTsPath}"`,
    `--ts_proto_out=${path.join(__dirname, 'src/proto/')}`,
    `--proto_path=${protoDir}`,
    'jscp-protocol.proto',
];
console.log(`protoc ${args.join(' ')}`);
childProcess.spawn(`protoc${exeExt}`, args, {
    stdio: 'inherit',
});
