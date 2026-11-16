import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { demoHamming } from './hamming.js';
import { demoSymmetricCrypto } from './symmetric_crypto.js';

const outDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'output');
fs.mkdirSync(outDir, { recursive: true });

const results = {
  hamming: demoHamming(),
  symmetric: await demoSymmetricCrypto(),
};

fs.writeFileSync(path.join(outDir, 'results.json'), JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
