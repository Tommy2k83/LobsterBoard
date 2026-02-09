import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import babel from '@rollup/plugin-babel';
import terser from '@rollup/plugin-terser';
import postcss from 'rollup-plugin-postcss';

export default [
  // Main builds (UMD + ESM)
  {
    input: 'src/index.js',
    output: [
      {
        file: 'dist/lobsterboard.umd.js',
        format: 'umd',
        name: 'LobsterBoard',
        sourcemap: true,
      },
      {
        file: 'dist/lobsterboard.esm.js',
        format: 'esm',
        sourcemap: true,
      },
    ],
    plugins: [
      postcss({
        extract: 'lobsterboard.css',
        minimize: false,
        sourceMap: true,
      }),
      resolve(),
      commonjs(),
      babel({
        exclude: 'node_modules/**',
        babelHelpers: 'bundled',
        presets: [['@babel/preset-env', { targets: 'defaults' }]],
      }),
    ],
  },
  // Minified builds
  {
    input: 'src/index.js',
    output: [
      {
        file: 'dist/lobsterboard.umd.min.js',
        format: 'umd',
        name: 'LobsterBoard',
        sourcemap: true,
        plugins: [terser()],
      },
      {
        file: 'dist/lobsterboard.esm.min.js',
        format: 'esm',
        sourcemap: true,
        plugins: [terser()],
      },
    ],
    plugins: [
      postcss({
        extract: 'lobsterboard.min.css',
        minimize: true,
        sourceMap: true,
      }),
      resolve(),
      commonjs(),
      babel({
        exclude: 'node_modules/**',
        babelHelpers: 'bundled',
        presets: [['@babel/preset-env', { targets: 'defaults' }]],
      }),
    ],
  },
];
