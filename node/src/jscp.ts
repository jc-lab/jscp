import { Go } from './tinygo_wasm_exec';
import { GoWasmHelper, RefId } from 'go-wasm-helper';
import loadCoreWasm from './jscp.wasm';

class Base {
  protected helper!: GoWasmHelper;

  protected start(): Promise<void> {
    const go = new Go();
    go.argv = process.argv.slice(2);
    go.env = Object.assign({ TMPDIR: require("os").tmpdir() }, process.env);

    const helper = new GoWasmHelper(go);
    this.helper = helper;

    return loadCoreWasm(helper.go.importObject)
      .then(({instance}) => {
        helper.run(instance);
      });
  }
}

export class Server extends Base {
  private _instance!: RefId;

  public start(): Promise<void> {
    return super.start()
      .then(() => {
        this._instance = this.helper.callFunction('newServer', 0n);
      });
  }
}

export class Client extends Base {
  private _instance!: RefId;

  public start(): Promise<void> {
    return super.start()
      .then(() => {
        this._instance = this.helper.callFunction('newClient', 0n);
      });
  }
}
//make pb