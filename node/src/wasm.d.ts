declare module "*.wasm" {
  const content: (options?: any) => Promise<WebAssembly.WebAssemblyInstantiatedSource>;
  export default content;
}