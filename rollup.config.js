// @rollup/plugin-typescript: faster, but I couldn't get it to properly emit declaration files
// rollup-plugin-typescript2: couldn't get it to respect output.file instead of tsconfig.json
import typescript from 'rollup-plugin-ts';

import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import polyfill from 'rollup-plugin-polyfill-node';
import {terser} from 'rollup-plugin-terser';
import deno from 'rollup-plugin-deno';
import pkg from './package.json';

const clean = {comments: /[^\w\W]/};

// somewhat hacky, but official, way to prevent redundant declaration files
const suppressDuplicateDeclarations = {
  outputPath: (path, kind) =>
    kind === 'declaration' ? './dist/index.d.ts' : path,
};

const builds = [
  {
    input: 'src/electionguard/index.ts',
    output: [
      {file: pkg.exports.import, format: 'esm'},
      {file: pkg.exports.require, format: 'cjs'},
    ],
    plugins: [
      commonjs(),
      typescript({hook: suppressDuplicateDeclarations}),
      terser({
        output: clean,
      }),
    ],
    external: [
      'bigint-mod-arith',
      'io-ts/Decoder',
      'io-ts/Encoder',
      'io-ts/Codec',
      'fp-ts/function',
      'fp-ts/lib/Either',
      'randombytes',
      'create-hash',
      'create-hmac',
      'seedrandom',
      '@stdlib/assert-has-arrow-function-support',
      '@stdlib/assert-has-async-await-support',
      '@stdlib/assert-has-bigint-support',
      '@stdlib/assert-has-class-support',
      '@stdlib/assert-has-map-support',
      '@stdlib/assert-has-set-support',
      '@stdlib/assert-has-uint8array-support',
    ],
  },
  {
    input: 'src/electionguard/index.ts',
    output: [{file: 'dist/mod.js', format: 'esm'}],
    context: 'this',
    plugins: [
      commonjs(),
      resolve({preferBuiltins: false, browser: false}),
      typescript({hook: suppressDuplicateDeclarations}),
      deno(),
      terser({
        output: clean,
      }),
    ],
    external: ['https://deno.land/std@0.90.0/node/crypto.ts'],
  },
  {
    input: 'src/electionguard/index.ts',
    output: [
      {file: pkg.browser, format: 'esm'},
      {
        file: 'dist/electionguard.umd.js',
        name: 'eg',
        format: 'umd',
      },
    ],
    context: 'this',
    plugins: [
      commonjs(),
      resolve({preferBuiltins: false, browser: true}),
      polyfill(),
      typescript({hook: suppressDuplicateDeclarations}),
      terser({
        output: clean,
      }),
    ],
  },
];

export default builds;
