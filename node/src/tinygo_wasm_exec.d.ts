export class Go {
  public argv: string[];
  public env: Record<string, string> & any;
  // public exit: any; not used in tinygo
  public exited: boolean;
  public importObject: {
    env: ModuleImports,
    gojs: ModuleImports,
  } & WebAssembly.Imports;
  public _pendingEvent: any;

  public _resume(): void;

  public run(instance: any): Promise<void>;
}
