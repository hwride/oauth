/**
 * Convert an array buffer to a human-readable binary string.
 *
 * E.g. toBinary(buffer) => '11111111'
 *      toBinary(buffer) => '1111111111111111'
 *      toBinary(buffer) => '11111111 11111111' // spaces = false
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
 *      toHex(buffer) => '12af3b' // spaces = false
 */
export function toHex(buffer: ArrayBuffer, spaces = true) {
  const byteStrings = [];
  for (const byte of new Uint8Array(buffer)) {
    byteStrings.push(byte.toString(16).padStart(2, "0"));
  }
  return byteStrings.join(spaces ? " " : "");
}

/**
 * Convert a binary string to an ArrayBuffer.
 *
 * E.g. binaryToArrayBuffer('11110000')
 *
 * Spaces can be used anywhere in the string, e.g.:
 *      binaryToArrayBuffer('1111 0000')
 *
 * But note they contain no semantic significance and are stripped. Every 8
 * bits will be the next byte regardless of spaces, e.g.:
 *      binaryToArrayBuffer('1111 0000')
 *       ===
 *      binaryToArrayBuffer('11 1 1 000 0')
 *
 * @param binary Binary string, e.g. 11110000 or 1111 0000. Spaces are ignored.
 */
export function binaryToArrayBuffer(binary: string): ArrayBuffer {
  if (!/^[01\s]+$/i.test(binary)) {
    throw new Error("Hex string must contain binary digits");
  }

  const binaryStripped = binary.replace(/\s+/g, "");
  const buffer = new ArrayBuffer(Math.ceil(binaryStripped.length / 8));
  const bytes = new Uint8Array(buffer);

  for (let i = 0; i < bytes.length; i++) {
    const byte = binaryStripped.slice(i * 8, i * 8 + 8);
    const numberVal = Number.parseInt(byte, 2);
    bytes[i] = numberVal;
  }

  return buffer;
}

/**
 * Convert a hex string to an ArrayBuffer.
 *
 * E.g. hexToArrayBuffer('12af3b')
 *
 * Spaces can be used anywhere in the string, e.g.:
 *      binaryToArrayBuffer('12 af 3b')
 *
 * But note they contain no semantic significance and are stripped. Every 2
 * characters will be the next byte regardless of spaces, e.g.:
 *      binaryToArrayBuffer('12 af 3b')
 *       ===
 *      binaryToArrayBuffer('1 2 af3 b')
 *
 * @param hex Hex string, e.g. 12af3b or 12 af 3b. Spaces are ignored.
 */
export function hexToArrayBuffer(hex: string): ArrayBuffer {
  if (!/^[0-9a-f\s]+$/i.test(hex)) {
    throw new Error("Hex string must contain pairs of hexadecimal digits");
  }

  const hexStripped = hex.replace(/\s+/g, "");
  const buffer = new ArrayBuffer(Math.ceil(hexStripped.length / 2));
  const bytes = new Uint8Array(buffer);

  for (let i = 0; i < bytes.length; i++) {
    const byte = hexStripped.slice(i * 2, i * 2 + 2);
    bytes[i] = Number.parseInt(byte, 16);
  }

  return buffer;
}
