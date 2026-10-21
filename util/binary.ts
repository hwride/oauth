/**
 * Convert an array buffer to a human-readable binary string.
 *
 * E.g. toHex(buffer) => '11111111'
 */
export function toBinary(buffer: ArrayBuffer, spaces = true) {
  const byteStrings = [];
  for (const byte of new Uint8Array(buffer)) {
    byteStrings.push(byte.toString(2).padStart(8, "0"));
  }
  return byteStrings.join(spaces ? " " : "");
}

/**
 * Convert an array buffer to a human-readable hex string.
 *
 * E.g. toHex(buffer) => '12 af 3b'
 */
export function toHex(buffer: ArrayBuffer, spaces = true) {
  const byteStrings = [];
  for (const byte of new Uint8Array(buffer)) {
    byteStrings.push(byte.toString(16).padStart(2, "0"));
  }
  return byteStrings.join(spaces ? " " : "");
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
