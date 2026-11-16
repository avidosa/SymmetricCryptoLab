// Demos con salida pensada para leerse en la terminal:
//   node demo.js hamming      matrices, errores simples corregidos y un error doble mal corregido
//   node demo.js cbc          mi CBC a mano contra el de WebCrypto
//   node demo.js manipulacion CBC deja pasar un mensaje cambiado; GCM y ChaCha20-Poly1305 lo rechazan
import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { G, H, encode, correct, computeProbabilities } from './hamming.js';
import {
  aesCbcEncryptManual, aesCbcDecryptManual, aesCbcEncryptSubtle, pkcs7Pad,
  aesGcmEncrypt, aesGcmDecrypt, chacha20Poly1305Encrypt, chacha20Poly1305Decrypt, TEST_MESSAGES,
} from './symmetric_crypto.js';

const bits = (v) => v.join('');
const si = (x) => (x ? 'sí' : 'NO');

function hamming() {
  console.log('G (4×7)            H (3×7)');
  G.forEach((f, i) => console.log(`  ${f.join(' ')}          ${H[i] ? H[i].join(' ') : ''}`));

  console.log('\nUn error simple se corrige:');
  console.log('  mensaje  código    recibido  síndrome  posición  corregido  mensaje');
  [[1, 0, 1, 1], [0, 1, 1, 0], [1, 1, 0, 0]].forEach((m, i) => {
    const c = encode(m);
    const r = [...c];
    r[i + 1] ^= 1;
    const x = correct(r);
    console.log(`  ${bits(m)}     ${bits(c)}   ${bits(r)}   ${bits(x.syndrome)}       ${x.errorPosition}         ${bits(x.corrected)}    ${bits(x.corrected.slice(0, 4))}`);
  });

  console.log('\nUn error DOBLE se detecta (síndrome ≠ 000), pero el decodificador lo "corrige" mal:');
  const m = [1, 0, 1, 1];
  const c = encode(m);
  const r = [...c];
  r[0] ^= 1;
  r[4] ^= 1;
  const x = correct(r);
  console.log(`  enviado   ${bits(c)}  (mensaje ${bits(m)})`);
  console.log(`  recibido  ${bits(r)}  síndrome ${bits(x.syndrome)}  → voltea el bit ${x.errorPosition}`);
  console.log(`  devuelve  ${bits(x.corrected)}  (mensaje ${bits(x.corrected.slice(0, 4))})  ← distinto del original`);

  const p = computeProbabilities(0.01);
  console.log('\nCanal con p = 0,01:');
  console.log(`  sin errores                 ${p.pNoError.toFixed(12)}`);
  console.log(`  un error (se corrige)       ${p.pCorrectableError.toFixed(12)}`);
  console.log(`  error NO detectado          ${p.pUndetected.toExponential(6)}`);
  console.log(`  decodificación correcta     ${p.pSuccessfulDecoding.toFixed(12)}`);
}

async function cbc() {
  const clave = randomBytes(16);
  const iv = randomBytes(16);
  console.log(`clave ${clave.toString('hex')}\niv    ${iv.toString('hex')}\n`);
  console.log('  bytes  tras pad  CBC a mano = WebCrypto  descifra bien   mensaje');
  for (const t of TEST_MESSAGES) {
    const msg = Buffer.from(t);
    const manual = aesCbcEncryptManual(msg, clave, iv);
    const web = await aesCbcEncryptSubtle(msg, clave, iv);
    const ok = aesCbcDecryptManual(manual, clave, iv).equals(msg);
    const corto = t.length > 34 ? t.slice(0, 31) + '...' : t;
    console.log(`  ${String(msg.length).padStart(5)}  ${String(pkcs7Pad(msg).length).padStart(7)}  ${si(manual.equals(web)).padStart(22)}  ${si(ok).padStart(12)}   ${corto || '(vacío)'}`);
  }
}

async function manipulacion() {
  const original = 'Pago: 100 EUR a Ana';
  console.log(`mensaje original:  ${original}\n`);

  const clave = randomBytes(16);
  const iv = randomBytes(16);
  const cifrado = aesCbcEncryptManual(Buffer.from(original), clave, iv);
  const ivTocado = Buffer.from(iv);
  ivTocado[6] ^= '1'.charCodeAt(0) ^ '9'.charCodeAt(0); // sin conocer la clave
  console.log('AES-CBC (sin autenticación)');
  console.log('  cambio un byte del IV sin saber la clave...');
  console.log(`  descifra sin quejarse: ${aesCbcDecryptManual(cifrado, clave, ivTocado).toString()}`);

  console.log('\nAES-GCM');
  const kg = randomBytes(16), ig = randomBytes(12);
  const cg = await aesGcmEncrypt(original, kg, ig);
  const tocadoG = Buffer.from(cg);
  tocadoG[6] ^= 1;
  try { await aesGcmDecrypt(tocadoG, kg, ig); console.log('  ¡lo aceptó!'); } catch (e) { console.log(`  cambio un bit del cifrado → rechazado (${e.name})`); }

  console.log('\nChaCha20-Poly1305');
  const kc = randomBytes(32), nc = randomBytes(12);
  const { ciphertext, tag } = chacha20Poly1305Encrypt(original, kc, nc);
  const ctTocado = Buffer.from(ciphertext);
  ctTocado[6] ^= 1;
  try { chacha20Poly1305Decrypt(ctTocado, kc, nc, tag); console.log('  ¡lo aceptó!'); } catch (e) { console.log(`  cambio un bit del cifrado → rechazado (${e.message})`); }
}

const cual = process.argv[2];
if (cual === 'hamming') hamming();
else if (cual === 'cbc') await cbc();
else if (cual === 'manipulacion') await manipulacion();
else console.log('uso: node demo.js hamming | cbc | manipulacion');
