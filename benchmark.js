// AES-GCM contra ChaCha20-Poly1305, esta vez con la misma vara de medir.
//
// En la primera medición salía ChaCha ~12 veces más rápido. Pero allí AES-GCM iba por WebCrypto (asíncrono y
// re-importando la clave en cada vuelta) y ChaCha por node:crypto (síncrono, con la clave ya hecha).
// Aquí comparo ambos por la MISMA API, con clave de 256 bits y un nonce nuevo en cada operación, y
// dejo WebCrypto aparte para ver cuánto pesa cada cosa.
import { createCipheriv, randomBytes, webcrypto } from 'node:crypto';
import { performance } from 'node:perf_hooks';

const subtle = webcrypto.subtle;
const clave = randomBytes(32);

function sellar(alg, msg) {
  const c = createCipheriv(alg, clave, randomBytes(12), { authTagLength: 16 });
  return Buffer.concat([c.update(msg), c.final(), c.getAuthTag()]);
}

// Mediana de varias tandas, intercalando los algoritmos: un solo número en un portátil es ruido.
async function tanda(fn, vueltas) {
  const t0 = performance.now();
  for (let i = 0; i < vueltas; i++) await fn();
  return (performance.now() - t0) / vueltas; // ms por operación
}
const mediana = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const TANDAS = 7;

const casos = [
  { nombre: '61 B (el mensaje de la primera medición)', bytes: 61, vueltas: 28000 },
  { nombre: '16 KiB', bytes: 16 * 1024, vueltas: 7000 },
  { nombre: '1 MiB', bytes: 1024 * 1024, vueltas: 140 },
];

const claveWeb = await subtle.importKey('raw', clave, { name: 'AES-GCM' }, false, ['encrypt']);
const filas = [];
for (const { nombre, bytes, vueltas } of casos) {
  const msg = randomBytes(bytes);
  const pruebas = {
    'AES-256-GCM    node:crypto': () => sellar('aes-256-gcm', msg),
    'ChaCha20-Poly  node:crypto': () => sellar('chacha20-poly1305', msg),
    'AES-GCM  WebCrypto, clave importada 1 vez': () =>
      subtle.encrypt({ name: 'AES-GCM', iv: randomBytes(12) }, claveWeb, msg),
    'AES-GCM  WebCrypto, importando cada vez (como el original)': async () => {
      const k = await subtle.importKey('raw', clave, { name: 'AES-GCM' }, false, ['encrypt']);
      return subtle.encrypt({ name: 'AES-GCM', iv: randomBytes(12) }, k, msg);
    },
  };
  const tiempos = Object.fromEntries(Object.keys(pruebas).map((k) => [k, []]));
  for (const fn of Object.values(pruebas)) await tanda(fn, Math.min(50, vueltas)); // calentar
  for (let t = 0; t < TANDAS; t++) {
    for (const [alg, fn] of Object.entries(pruebas)) tiempos[alg].push(await tanda(fn, Math.ceil(vueltas / TANDAS)));
  }
  filas.push([nombre, bytes, Object.fromEntries(Object.entries(tiempos).map(([k, v]) => [k, mediana(v)]))]);
}

for (const [nombre, bytes, r] of filas) {
  console.log(`\n${nombre}   (mediana de ${TANDAS} tandas)`);
  for (const [alg, ms] of Object.entries(r)) {
    const mbs = bytes / 1048576 / (ms / 1000);
    console.log(`  ${alg.padEnd(60)} ${ms.toFixed(4).padStart(9)} ms/op   ${mbs.toFixed(0).padStart(6)} MiB/s`);
  }
}
