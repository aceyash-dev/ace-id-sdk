import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'server/index': 'src/server/index.ts',
    'react/index': 'src/react/index.ts',
    diagnostics: 'src/diagnostics.ts',
    'testing/oidc-mock': 'src/testing/oidc-mock.ts',
  },
  external: ['react'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  treeshake: true,
  splitting: false,
  target: 'es2022',
});
