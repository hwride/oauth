/**
 * Converts an ArrayBuffer into its binary string representation.
 *
 * E.g. 11111111 00000000 10110101
 */
export function getBufferAsBinaryStr(buffer: ArrayBuffer) {
  const uint8View = new Uint8Array(buffer);
  return [...uint8View]
    .map((byte) => byte.toString(2).padStart(8, "0"))
    .join(" ");
}

/**
 * Whether the current platform is big endian or little endian.
 */
export function getPlatformEndianness(): "big-endian" | "little-endian" {
  // Create a 16 bit int, this will be laid out according to the platform's endian-ness.
  const uInt16Bit = new Uint16Array([0xff00]);

  // Create a unsigned 8 bit view over that same bit of memory and read the first byte.
  // This will tell us if the platform is big endian or little endian.
  const uInt8Bit = new Uint8Array(uInt16Bit);
  const firstByte = uInt8Bit[0];
  return firstByte === 0xff ? "big-endian" : "little-endian";
}
