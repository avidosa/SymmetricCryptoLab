import { Buffer } from 'node:buffer';
import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual, webcrypto } from 'node:crypto';
import { performance } from 'node:perf_hooks';

const subtle = webcrypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const TEST_MESSAGES = [
  '',
  'Hola',
  '1234567890ABCDE',
  '1234567890ABCDEF',
  'Mensaje corto para AES',
  'Criptografía simétrica',
  'Este mensaje tiene exactamente treinta y dos bytes!!',
  'Una prueba algo más larga para verificar correctamente el padding y el unpadding en bloques de 16 bytes.',
  '😀 Unicode + acentos + símbolos € ñ ç',
  'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec et massa a augue feugiat imperdiet.',
];

export function pkcs7Pad(data, blockSize = 16) {
  const padLen = blockSize - (data.length % blockSize || blockSize % blockSize);
  const effectivePad = padLen === 0 ? blockSize : padLen;
  return Buffer.concat([data, Buffer.alloc(effectivePad, effectivePad)]);
}

export function pkcs7Unpad(data, blockSize = 16) {
  if (data.length === 0 || data.length % blockSize !== 0) {
    throw new Error('Longitud inválida para PKCS#7.');
  }
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > blockSize) {
    throw new Error('Padding PKCS#7 inválido.');
  }
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error('Padding PKCS#7 corrupto.');
  }
  return data.subarray(0, data.length - padLen);
}

export function xorBuffers(a, b) {
  if (a.length !== b.length) throw new Error('Los buffers deben tener la misma longitud para XOR.');
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

export function aesBlockEncrypt(block, key) {
  if (block.length !== 16 || key.length !== 16) throw new Error('AES-128 requiere bloques y clave de 16 bytes.');
  const cipher = createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

export function aesBlockDecrypt(block, key) {
  if (block.length !== 16 || key.length !== 16) throw new Error('AES-128 requiere bloques y clave de 16 bytes.');
  const decipher = createDecipheriv('aes-128-ecb', key, null);
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(block), decipher.final()]);
}

export function aesCbcEncryptManual(plaintext, key, iv) {
  const padded = pkcs7Pad(Buffer.from(plaintext));
  let previous = Buffer.from(iv);
  const blocks = [];
  for (let i = 0; i < padded.length; i += 16) {
    const block = padded.subarray(i, i + 16);
    const xored = xorBuffers(block, previous);
    const encrypted = aesBlockEncrypt(xored, key);
    blocks.push(encrypted);
    previous = encrypted;
  }
  return Buffer.concat(blocks);
}

export function aesCbcDecryptManual(ciphertext, key, iv) {
  let previous = Buffer.from(iv);
  const blocks = [];
  for (let i = 0; i < ciphertext.length; i += 16) {
    const block = ciphertext.subarray(i, i + 16);
    const decrypted = aesBlockDecrypt(block, key);
    const plainBlock = xorBuffers(decrypted, previous);
    blocks.push(plainBlock);
    previous = block;
  }
  return pkcs7Unpad(Buffer.concat(blocks));
}

export async function subtleImportAesKey(rawKey, usage = ['encrypt', 'decrypt']) {
  return subtle.importKey('raw', rawKey, { name: 'AES-CBC' }, false, usage);
}

export async function aesCbcEncryptSubtle(plaintext, rawKey, iv) {
  const key = await subtleImportAesKey(rawKey);
  const ct = await subtle.encrypt({ name: 'AES-CBC', iv }, key, plaintext);
  return Buffer.from(ct);
}

export async function aesCbcDecryptSubtle(ciphertext, rawKey, iv) {
  const key = await subtleImportAesKey(rawKey);
  const pt = await subtle.decrypt({ name: 'AES-CBC', iv }, key, ciphertext);
  return Buffer.from(pt);
}

export function otpEncrypt(messageBuffer, keyBuffer) {
  if (keyBuffer.length < messageBuffer.length) {
    throw new Error('La clave OTP debe ser al menos tan larga como el mensaje.');
  }
  const paddedMessage = Buffer.concat([messageBuffer, Buffer.alloc(keyBuffer.length - messageBuffer.length, 0)]);
  return {
    paddedMessage,
    ciphertext: xorBuffers(paddedMessage, keyBuffer),
  };
}

export function otpDecrypt(ciphertext, keyBuffer, originalLength) {
  const padded = xorBuffers(ciphertext, keyBuffer);
  return padded.subarray(0, originalLength);
}

export async function aesGcmEncrypt(message, rawKey, iv) {
  const key = await subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  const encrypted = await subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(message));
  return Buffer.from(encrypted);
}

export async function aesGcmDecrypt(ciphertext, rawKey, iv) {
  const key = await subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  const decrypted = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return decoder.decode(decrypted);
}

export function chacha20Poly1305Encrypt(message, key, nonce) {
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  const ciphertext = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, tag };
}

export function chacha20Poly1305Decrypt(ciphertext, key, nonce, tag) {
  const decipher = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

export async function benchmark(fn, iterations = 300) {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    await fn();
  }
  const end = performance.now();
  return (end - start) / iterations;
}

export async function demoSymmetricCrypto() {
  const aesKey = randomBytes(16);
  const iv = randomBytes(16);
  const messages = TEST_MESSAGES.map((message) => Buffer.from(message, 'utf8'));

  const padChecks = messages.map((buffer) => {
    const padded = pkcs7Pad(buffer);
    const unpadded = pkcs7Unpad(padded);
    return {
      original: buffer.toString('utf8'),
      ok: timingSafeEqual(Buffer.from(buffer), Buffer.from(unpadded)),
      originalLength: buffer.length,
      paddedLength: padded.length,
    };
  });

  const cbcComparisons = [];
  for (const msg of messages) {
    const manual = aesCbcEncryptManual(msg, aesKey, iv);
    const subtleCt = await aesCbcEncryptSubtle(msg, aesKey, iv);
    const manualDec = aesCbcDecryptManual(manual, aesKey, iv);
    const subtleDec = await aesCbcDecryptSubtle(subtleCt, aesKey, iv);
    cbcComparisons.push({
      message: msg.toString('utf8'),
      sameCiphertext: manual.equals(subtleCt),
      samePlaintextAfterDecrypt: manualDec.equals(subtleDec) && manualDec.equals(msg),
      ciphertextHexPreview: manual.subarray(0, 16).toString('hex'),
      ciphertextLength: manual.length,
    });
  }

  const otpMessage = Buffer.from('OTP de ejemplo con Buffer', 'utf8');
  const otpKey = randomBytes(otpMessage.length + 8);
  const otp = otpEncrypt(otpMessage, otpKey);
  const otpRecovered = otpDecrypt(otp.ciphertext, otpKey, otpMessage.length);

  const authMessage = 'Mensaje autenticado para comparar AES-GCM y ChaCha20-Poly1305';
  const aesGcmKey = randomBytes(16);
  const aesGcmIv = randomBytes(12);
  const chachaKey = randomBytes(32);
  const chachaNonce = randomBytes(12);

  const aesGcmCiphertext = await aesGcmEncrypt(authMessage, aesGcmKey, aesGcmIv);
  const aesGcmRecovered = await aesGcmDecrypt(aesGcmCiphertext, aesGcmKey, aesGcmIv);

  const chachaEncrypted = chacha20Poly1305Encrypt(authMessage, chachaKey, chachaNonce);
  const chachaRecovered = chacha20Poly1305Decrypt(
    chachaEncrypted.ciphertext,
    chachaKey,
    chachaNonce,
    chachaEncrypted.tag,
  );

  const aesGcmMs = await benchmark(() => aesGcmEncrypt(authMessage, aesGcmKey, aesGcmIv), 300);
  const chachaMs = await benchmark(() => Promise.resolve(chacha20Poly1305Encrypt(authMessage, chachaKey, chachaNonce)), 300);

  return {
    padChecks,
    cbcComparisons,
    otp: {
      message: otpMessage.toString('utf8'),
      originalLength: otpMessage.length,
      keyLength: otpKey.length,
      recoveredMatches: otpRecovered.equals(otpMessage),
      ciphertextHexPreview: otp.ciphertext.subarray(0, 16).toString('hex'),
    },
    authenticatedEncryption: {
      message: authMessage,
      aesGcm: {
        ciphertextLength: aesGcmCiphertext.length,
        recoveredMatches: aesGcmRecovered === authMessage,
        averageMs: Number(aesGcmMs.toFixed(6)),
      },
      chacha20Poly1305: {
        ciphertextLength: chachaEncrypted.ciphertext.length + chachaEncrypted.tag.length,
        recoveredMatches: chachaRecovered === authMessage,
        averageMs: Number(chachaMs.toFixed(6)),
      },
    },
  };
}
