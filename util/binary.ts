/**
 * Convert an array buffer to a human-readable hex string.
 *
 * E.g. toHex(buffer) => '12af3b'
 */
export function toHex(buffer: ArrayBuffer) {
  let hexStr = "";
  for (const byte of new Uint8Array(buffer)) {
    hexStr += byte.toString(16);
  }
  return hexStr;
}

/**
 * Convert a hex string to an ArrayBuffer.
 *
 * E.g. hexToArrayBuffer('12af3b')
 */
export function hexToArrayBuffer(hex: string): ArrayBuffer {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(hex)) {
    throw new Error("Hex string must contain pairs of hexadecimal digits");
  }

  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);

  for (let i = 0; i < bytes.length; i++) {
    const byte = hex.slice(i * 2, i * 2 + 2);
    bytes[i] = Number.parseInt(byte, 16);
  }

  return buffer;
}
