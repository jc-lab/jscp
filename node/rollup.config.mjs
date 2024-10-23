import typescript from '@rollup/plugin-typescript';
import { wasm } from '@rollup/plugin-wasm';

/** @type {import('rollup').RollupOptions} */
const options = {
  input: './src/types.ts',
  output: {
    dir: './dist',
    format: 'esm',
  },
  plugins: [
    typescript({
      tsconfig: './tsconfig.lib.json',
      declarationDir: './dist'
    }),
    wasm({
      targetEnv: 'auto-inline',
    }),
  ],
};

export default options;