import test from 'node:test';
import assert from 'node:assert/strict';
import { G, encode, syndrome, correct, computeProbabilities } from '../hamming.js';

// los 16 mensajes posibles de 4 bits y sus 16 palabras de código
const mensajes = Array.from({ length: 16 }, (_, n) => [3, 2, 1, 0].map((b) => (n >> b) & 1));
const palabras = mensajes.map(encode);
const peso = (w) => w.reduce((a, b) => a + b, 0);

test('G y H son compatibles: toda palabra de código tiene síndrome 000', () => {
  for (const fila of G) assert.deepEqual(syndrome(fila), [0, 0, 0]);
  for (const c of palabras) assert.deepEqual(syndrome(c), [0, 0, 0]);
});

test('la distribución de pesos es A0=1, A3=7, A4=7, A7=1 (de ahí sale la fórmula de P_und)', () => {
  const A = {};
  for (const c of palabras) A[peso(c)] = (A[peso(c)] ?? 0) + 1;
  assert.deepEqual(A, { 0: 1, 3: 7, 4: 7, 7: 1 });
});

test('corrige TODOS los errores simples: 16 mensajes × 7 posiciones = 112 casos', () => {
  let casos = 0;
  mensajes.forEach((m, i) => {
    for (let pos = 0; pos < 7; pos++) {
      const recibida = [...palabras[i]];
      recibida[pos] ^= 1;
      const r = correct(recibida);
      assert.equal(r.errorPosition, pos + 1);
      assert.deepEqual(r.corrected, palabras[i]);
      assert.deepEqual(r.corrected.slice(0, 4), m);
      casos++;
    }
  });
  assert.equal(casos, 112);
});

test('los errores dobles SE DETECTAN pero NO se corrigen: el decodificador acaba en otra palabra válida', () => {
  let casos = 0;
  palabras.forEach((c) => {
    for (let a = 0; a < 7; a++) {
      for (let b = a + 1; b < 7; b++) {
        const recibida = [...c];
        recibida[a] ^= 1;
        recibida[b] ^= 1;
        assert.notDeepEqual(syndrome(recibida), [0, 0, 0]); // detectado
        const r = correct(recibida);
        assert.notDeepEqual(r.corrected, c); // pero «corregido» mal
        assert.deepEqual(syndrome(r.corrected), [0, 0, 0]); // y lo que devuelve parece válido
        casos++;
      }
    }
  });
  assert.equal(casos, 16 * 21);
});

test('las probabilidades de la fórmula coinciden con enumerar los 128 patrones de error posibles', () => {
  const p = 0.01;
  const codigos = new Set(palabras.map((c) => c.join('')));
  let sinError = 0, unError = 0, noDetectado = 0, total = 0;
  for (let e = 0; e < 128; e++) {
    const patron = Array.from({ length: 7 }, (_, i) => (e >> (6 - i)) & 1);
    const w = peso(patron);
    const prob = p ** w * (1 - p) ** (7 - w);
    total += prob;
    if (w === 0) sinError += prob;
    else if (w === 1) unError += prob;
    // error no detectable: el patrón de error es, él mismo, una palabra de código no nula
    if (w > 0 && codigos.has(patron.join(''))) noDetectado += prob;
  }
  const f = computeProbabilities(p);
  assert.ok(Math.abs(total - 1) < 1e-12);
  assert.ok(Math.abs(f.pNoError - sinError) < 1e-15);
  assert.ok(Math.abs(f.pCorrectableError - unError) < 1e-15);
  assert.ok(Math.abs(f.pUndetected - noDetectado) < 1e-15);
});

test('rechaza longitudes incorrectas', () => {
  assert.throws(() => encode([1, 0, 1]));
  assert.throws(() => syndrome([1, 0, 1, 1, 0, 1]));
});
