import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import {
  aesBlockEncrypt, aesBlockDecrypt, aesCbcEncryptManual, aesCbcDecryptManual, aesCbcEncryptSubtle,
  pkcs7Pad, pkcs7Unpad, xorBuffers, otpEncrypt, otpDecrypt,
  aesGcmEncrypt, aesGcmDecrypt, chacha20Poly1305Encrypt, chacha20Poly1305Decrypt,
} from '../symmetric_crypto.js';

const hex = (s) => Buffer.from(s, 'hex');

test('AES-128 contra el vector oficial de FIPS-197 (apéndice C.1)', () => {
  const clave = hex('000102030405060708090a0b0c0d0e0f');
  const claro = hex('00112233445566778899aabbccddeeff');
  const cifrado = aesBlockEncrypt(claro, clave);
  assert.equal(cifrado.toString('hex'), '69c4e0d86a7b0430d8cdb78070b4c55a');
  assert.equal(aesBlockDecrypt(cifrado, clave).toString('hex'), claro.toString('hex'));
});

test('CBC a mano contra el vector oficial de NIST SP 800-38A (F.2.1)', () => {
  const clave = hex('2b7e151628aed2a6abf7158809cf4f3c');
  const iv = hex('000102030405060708090a0b0c0d0e0f');
  const claro = hex('6bc1bee22e409f96e93d7e117393172a' + 'ae2d8a571e03ac9c9eb76fac45af8e51');
  // el vector de NIST no lleva padding; mi función sí, así que comparo los dos primeros bloques
  const cifrado = aesCbcEncryptManual(claro, clave, iv);
  assert.equal(
    cifrado.subarray(0, 32).toString('hex'),
    '7649abac8119b246cee98e9b12e9197d' + '5086cb9b507219ee95db113a917678b2',
  );
});

test('CBC a mano == CBC de WebCrypto en 200 mensajes aleatorios (longitud 0–200)', async () => {
  for (let i = 0; i < 200; i++) {
    const clave = randomBytes(16);
    const iv = randomBytes(16);
    const msg = randomBytes(Math.floor(Math.random() * 201));
    const manual = aesCbcEncryptManual(msg, clave, iv);
    assert.ok(manual.equals(await aesCbcEncryptSubtle(msg, clave, iv)));
    assert.ok(aesCbcDecryptManual(manual, clave, iv).equals(msg));
  }
});

test('PKCS#7: añade entre 1 y 16 bytes, ida y vuelta, y rechaza padding roto', () => {
  for (let n = 0; n <= 40; n++) {
    const msg = randomBytes(n);
    const p = pkcs7Pad(msg);
    assert.equal(p.length % 16, 0);
    assert.ok(p.length - n >= 1 && p.length - n <= 16);
    assert.ok(pkcs7Unpad(p).equals(msg));
  }
  const malo = (ultimo, relleno) => Buffer.concat([Buffer.alloc(15, relleno), Buffer.from([ultimo])]);
  assert.throws(() => pkcs7Unpad(malo(0, 0)));      // longitud 0
  assert.throws(() => pkcs7Unpad(malo(17, 17)));    // mayor que el bloque
  assert.throws(() => pkcs7Unpad(malo(4, 9)));      // los bytes no son todos iguales
  assert.throws(() => pkcs7Unpad(Buffer.alloc(15))); // no es múltiplo de 16
});

test('OTP: ida y vuelta, clave corta rechazada, y reutilizar la clave la destroza', () => {
  const m1 = Buffer.from('ATACAR AL AMANECER');
  const m2 = Buffer.from('RETIRADA INMEDIATA');
  const k = randomBytes(m1.length);
  assert.ok(otpDecrypt(otpEncrypt(m1, k).ciphertext, k, m1.length).equals(m1));
  assert.throws(() => otpEncrypt(m1, randomBytes(3)));
  // «two-time pad»: con la misma clave, c1 XOR c2 = m1 XOR m2 y la clave desaparece
  const c1 = otpEncrypt(m1, k).ciphertext;
  const c2 = otpEncrypt(m2, k).ciphertext;
  assert.ok(xorBuffers(c1, c2).equals(xorBuffers(m1, m2)));
});

test('CBC NO detecta manipulaciones: cambiando el IV se cambia el primer bloque a voluntad', () => {
  const clave = randomBytes(16);
  const iv = randomBytes(16);
  const original = Buffer.from('Pago: 100 EUR a Ana');
  const cifrado = aesCbcEncryptManual(original, clave, iv);
  const ivTocado = Buffer.from(iv);
  ivTocado[6] ^= '1'.charCodeAt(0) ^ '9'.charCodeAt(0); // sin saber la clave
  const resultado = aesCbcDecryptManual(cifrado, clave, ivTocado); // no lanza ningún error
  assert.equal(resultado.toString(), 'Pago: 900 EUR a Ana');
});

test('AES-GCM y ChaCha20-Poly1305 SÍ detectan manipulaciones', async () => {
  const msg = 'Pago: 100 EUR a Ana';
  // GCM
  const kg = randomBytes(16), ig = randomBytes(12);
  const cg = await aesGcmEncrypt(msg, kg, ig);
  assert.equal(await aesGcmDecrypt(cg, kg, ig), msg);
  const tocadoG = Buffer.from(cg); tocadoG[3] ^= 1;
  await assert.rejects(() => aesGcmDecrypt(tocadoG, kg, ig));
  // ChaCha20-Poly1305
  const kc = randomBytes(32), nc = randomBytes(12);
  const { ciphertext, tag } = chacha20Poly1305Encrypt(msg, kc, nc);
  assert.equal(chacha20Poly1305Decrypt(ciphertext, kc, nc, tag), msg);
  const ctTocado = Buffer.from(ciphertext); ctTocado[3] ^= 1;
  assert.throws(() => chacha20Poly1305Decrypt(ctTocado, kc, nc, tag));
  const tagTocado = Buffer.from(tag); tagTocado[0] ^= 1;
  assert.throws(() => chacha20Poly1305Decrypt(ciphertext, kc, nc, tagTocado));
});
