export const G = [
  [1, 0, 0, 0, 1, 1, 0],
  [0, 1, 0, 0, 1, 0, 1],
  [0, 0, 1, 0, 0, 1, 1],
  [0, 0, 0, 1, 1, 1, 1],
];

export const H = [
  [1, 1, 0, 1, 1, 0, 0],
  [1, 0, 1, 1, 0, 1, 0],
  [0, 1, 1, 1, 0, 0, 1],
];

export function mod2(n) {
  return ((n % 2) + 2) % 2;
}

export function vectorTimesMatrixMod2(vector, matrix) {
  const cols = matrix[0].length;
  const out = Array(cols).fill(0);
  for (let j = 0; j < cols; j++) {
    let acc = 0;
    for (let i = 0; i < vector.length; i++) {
      acc += vector[i] * matrix[i][j];
    }
    out[j] = mod2(acc);
  }
  return out;
}

export function matrixTimesVectorMod2(matrix, vector) {
  return matrix.map((row) => mod2(row.reduce((acc, value, idx) => acc + value * vector[idx], 0)));
}

export function encode(messageBits) {
  if (messageBits.length !== 4) throw new Error('El mensaje debe tener 4 bits.');
  return vectorTimesMatrixMod2(messageBits, G);
}

export function syndrome(receivedWord) {
  if (receivedWord.length !== 7) throw new Error('La palabra recibida debe tener 7 bits.');
  return matrixTimesVectorMod2(H, receivedWord);
}

export function findErrorPosition(syndromeBits) {
  const columns = H[0].map((_, colIndex) => H.map((row) => row[colIndex]));
  const found = columns.findIndex((col) => col.every((bit, idx) => bit === syndromeBits[idx]));
  return found === -1 ? null : found + 1; // positions are 1-based
}

export function correct(receivedWord) {
  const syn = syndrome(receivedWord);
  const isZero = syn.every((bit) => bit === 0);
  const position = isZero ? null : findErrorPosition(syn);
  const corrected = [...receivedWord];
  if (position !== null) corrected[position - 1] ^= 1;
  return {
    received: [...receivedWord],
    syndrome: syn,
    errorPosition: position,
    corrected,
  };
}

export function messageFromCodeword(codeword) {
  return codeword.slice(0, 4);
}

export function binomial(n, k) {
  if (k < 0 || k > n) return 0;
  let res = 1;
  const kk = Math.min(k, n - k);
  for (let i = 1; i <= kk; i++) {
    res = (res * (n - kk + i)) / i;
  }
  return res;
}

export function probabilityExactWeight(n, k, p) {
  return binomial(n, k) * p ** k * (1 - p) ** (n - k);
}

export function formatProb(value) {
  return value.toFixed(12);
}

export function computeProbabilities(p = 0.01) {
  const pNoError = probabilityExactWeight(7, 0, p);
  const pOneError = probabilityExactWeight(7, 1, p);

  // Weight distribution of Hamming (7,4): A0=1, A3=7, A4=7, A7=1
  const pUndetected =
    7 * (p ** 3) * ((1 - p) ** 4) +
    7 * (p ** 4) * ((1 - p) ** 3) +
    (p ** 7);

  const pDetected = 1 - pNoError - pUndetected;
  const pCorrectableError = pOneError;
  const pSuccessfulDecoding = pNoError + pOneError;

  return {
    p,
    pNoError,
    pDetected,
    pCorrectableError,
    pUndetected,
    pSuccessfulDecoding,
  };
}

export function demoHamming() {
  const examples = [
    [1, 0, 1, 1],
    [0, 1, 1, 0],
    [1, 1, 0, 0],
  ].map((message, idx) => {
    const codeword = encode(message);
    const received = [...codeword];
    const flipPosition = idx + 2;
    received[flipPosition - 1] ^= 1;
    const result = correct(received);
    return {
      message,
      codeword,
      received,
      syndrome: result.syndrome,
      errorPosition: result.errorPosition,
      corrected: result.corrected,
      recoveredMessage: messageFromCodeword(result.corrected),
    };
  });

  return {
    G,
    H,
    probabilities: computeProbabilities(0.01),
    examples,
  };
}
