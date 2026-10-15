import {readFile} from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert/strict';

test('a lost-response result cannot become observed success or a retry control', async () => {
  const app = await readFile(new URL('../web/app.js', import.meta.url), 'utf8');
  assert.match(app, /unknown: .*unknown/);
  assert.match(app, /no automatic retry/);
  assert.doesNotMatch(app, /innerHTML|eval\(/);
});

test('receipt presentation separates unsigned display from native audit evidence', async () => {
  const receipt = await readFile(new URL('../web/receipt.html', import.meta.url), 'utf8');
  assert.match(receipt, /unsigned projections/);
  assert.match(receipt, /Missing signed observations stay missing/);
});
