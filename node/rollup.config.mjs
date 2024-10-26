import typescript from '@rollup/plugin-typescript';

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
  ],
};

export default options;