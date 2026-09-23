import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'ace-id-sdk': 'src/vanilla/index.ts',
  },
  format: ['iife'],
  globalName: 'AceID',
  platform: 'browser',
  target: 'es2022',
  bundle: true,
  sourcemap: true,
  minify: false,
  clean: false,
});
