#!/usr/bin/env node
/**
 * Bundle-size budget check.
 *
 * The SDK ships five entry points. Two of them are imported by every application
 * that signs a user in, so their size is a product decision, not a detail: a
 * login helper that costs 80 kB gzipped is a reason to reach for a competitor.
 *
 * The budgets are deliberately generous (they include the `jose` JWT library) but
 * finite, so an accidental dependency or a large table cannot land unnoticed.
 * Run after `npm run build`.
 */
import { gzipSync } from 'node:zlib';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const DIST = 'dist';

/** gzipped budget in kB per built file. */
const BUDGETS = {
  'index.js': 45,
  'index.cjs': 45,
  'react/index.js': 4,
  'server/index.js': 30,
  'diagnostics.js': 15,
  'testing/oidc-mock.js': 6,
};

/** Files that must stay free of runtime-only extras (peer dependencies). */
const FORBIDDEN = [
  { file: 'react/index.js', pattern: /\bfrom ['"]react-dom/, why: 'react-dom must not be bundled' },
  { file: 'index.js', pattern: /\bfrom ['"]react['"]/, why: 'react must not be bundled into the core entry' },
];

let failures = 0;

for (const [file, budgetKb] of Object.entries(BUDGETS)) {
  const path = join(DIST, file);
  let raw;
  try {
    raw = readFileSync(path);
  } catch {
    console.error(`✗ ${file}: missing — run "npm run build" first`);
    failures += 1;
    continue;
  }
  const gzippedKb = gzipSync(raw).length / 1024;
  const ok = gzippedKb <= budgetKb;
  const verdict = ok ? '✓' : '✗';
  console.log(
    `${verdict} ${file.padEnd(24)} ${gzippedKb.toFixed(1).padStart(6)} kB gzip` +
      ` (budget ${budgetKb} kB, raw ${(statSync(path).size / 1024).toFixed(1)} kB)`,
  );
  if (!ok) failures += 1;
}

for (const rule of FORBIDDEN) {
  const path = join(DIST, rule.file);
  let source;
  try {
    source = readFileSync(path, 'utf8');
  } catch {
    continue;
  }
  if (rule.pattern.test(source)) {
    console.error(`✗ ${rule.file}: ${rule.why}`);
    failures += 1;
  }
}

if (failures > 0) {
  console.error(`\n${failures} bundle-size check(s) failed.`);
  process.exit(1);
}
console.log('\nAll bundle-size checks passed.');
