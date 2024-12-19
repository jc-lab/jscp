import typescript from '@rollup/plugin-typescript';

/** @type {import('rollup').RollupOptions} */
const commonOptions = {
  plugins: [
    typescript({
      tsconfig: './tsconfig.lib.json',
      declarationDir: './lib'
    }),
  ],
};

/** @type {import('rollup').RollupOptions} */
const options = [
  {
    input: './src/index.ts',
    output: {
      file: './lib/index.mjs',
      format: 'esm',
    },
    ...commonOptions,
  },
  {
    input: './src/index.ts',
    output: {
      file: './lib/index.cjs',
      format: 'cjs',
    },
    ...commonOptions,
  }
];

export default options;