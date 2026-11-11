#!/usr/bin/env node
/**
 * Package verification.
 *
 * Runs after `npm run build` and checks the things a consumer would discover only
 * after installing the package:
 *
 * 1. every `exports` subpath resolves to files that actually exist, in both ESM
 *    and CJS form, with a matching `.d.ts`;
 * 2. each entry point is importable on its own — a broken subpath is a broken
 *    install, and `./server` or `./react` failing is invisible to a test that only
 *    imports the root;
 * 3. the package contains no leftover citation markers or absolute sandbox paths;
 * 4. README, LICENSE and the declaration files are present in the tarball payload.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
let failures = 0;

function fail(message) {
  console.error(`✗ ${message}`);
  failures += 1;
}

function pass(message) {
  console.log(`✓ ${message}`);
}

// 1. exports resolve
for (const [subpath, conditions] of Object.entries(pkg.exports ?? {})) {
  for (const [condition, target] of Object.entries(conditions)) {
    const path = join('.', target);
    if (existsSync(path)) continue;
    fail(`exports["${subpath}"].${condition} → ${target} does not exist`);
  }
}
if (failures === 0) pass(`all ${Object.keys(pkg.exports ?? {}).length} export subpaths resolve`);

// 2. each entry point imports standalone
const entryPoints = Object.entries(pkg.exports ?? {})
  .map(([subpath, conditions]) => [subpath, conditions.import])
  .filter(([, target]) => typeof target === 'string');

for (const [subpath, target] of entryPoints) {
  try {
    const module = await import(pathToFileURL(join('.', target)).href);
    if (!module || typeof module !== 'object') throw new Error('module did not evaluate');
    const named = Object.keys(module);
    if (named.length === 0) throw new Error('module exported nothing');
    pass(`./${subpath === '.' ? '' : subpath.slice(2)} imports standalone (${named.length} exports)`);
  } catch (error) {
    fail(`./${subpath} failed to import: ${error.message}`);
  }
}

// 3. no leaked markers or machine-specific paths
const artifacts = Object.values(pkg.exports ?? {})
  .flatMap((conditions) => Object.values(conditions))
  .filter((target) => typeof target === 'string');

for (const target of artifacts) {
  if (!existsSync(target)) continue;
  const source = readFileSync(target, 'utf8');
  if (source.includes('[cite:')) fail(`${target} contains a leftover citation marker`);
  if (/\/scratch\//.test(source)) fail(`${target} contains a machine-specific path`);
}

// 4. package payload
for (const file of ['README.md', 'LICENSE']) {
  if (existsSync(file)) pass(`${file} present`);
  else fail(`${file} missing from the repository root`);
}
for (const [subpath, conditions] of Object.entries(pkg.exports ?? {})) {
  const types = conditions.types;
  if (typeof types !== 'string') continue;
  if (existsSync(types)) continue;
  fail(`types for ./${subpath} missing: ${types}`);
}

if (pkg.version !== '0.2.4') fail(`expected version 0.2.4, found ${pkg.version}`);
else pass(`version is ${pkg.version}`);

if (failures > 0) {
  console.error(`\n${failures} package check(s) failed.`);
  process.exit(1);
}
console.log('\nAll package checks passed.');
