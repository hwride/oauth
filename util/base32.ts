import { binaryToArrayBuffer, toBinary } from "./binary.ts";

/**
 * Convert an array buffer to base32.
 *
 * RFC 4648: The Base16, Base32, and Base64 Data Encodings
 * https://www.rfc-editor.org/info/rfc4648
 */
export function toBase32(buffer: ArrayBuffer) {
  // We represent 5 bits per character by choosing a 32 character alphabet.
  // If not a multiple of 5 zero-pad. = is used at the end as the padding character. This is a 33rd char.
  // Each 40-bits of input becomes 8 characters (8 * 5 = 40).
  // If there are fewer than 40-bits available at the end of the encoding the bits are padded on the right with 0.
  // Any of the padding bytes not part of the real data should be encoded as the padding character =
  if (buffer.byteLength === 0) {
    return "";
  }

  const binaryStr = toBinary(buffer, false);

  // Split into 5-bit chunks.
  const chunks5Bit: string[] = [];
  for (let bitNum = 0; bitNum < binaryStr.length; bitNum += 5) {
    // Final chunk may be less than 5 bits depending on our input. Right pad with 0s if so.
    const chunk = binaryStr.slice(bitNum, bitNum + 5);
    const chunk5Bit = chunk.padEnd(5, "0");
    chunks5Bit.push(chunk5Bit);
  }

  // Split into 40-bit chunks. Base 32 always outputs in 40-bit/8 character chunks.
  const chunks40Bit: string[][] = [];
  for (let i = 0; i < chunks5Bit.length; i += 8) {
    const chunk40Bit = chunks5Bit.slice(i, i + 8);
    while (chunk40Bit.length < 8) {
      chunk40Bit.push("pad-bit"); // Pad with 5-bit chunks.
    }
    chunks40Bit.push(chunk40Bit);
  }

  // Loop over our chunks and create our base 32 string.
  let base32 = "";
  for (const chunks5Bit of chunks40Bit) {
    for (const chunk5Bit of chunks5Bit) {
      if (chunk5Bit === "pad-bit") {
        base32 += "=";
      } else {
        const chunk8BitsPadded = chunk5Bit.padStart(8, "0");
        const chunkBuffer = binaryToArrayBuffer(chunk8BitsPadded);
        const chunkValue = new Uint8Array(chunkBuffer)[0];
        const base32Char = base32Chars[chunkValue];
        base32 += base32Char;
      }
    }
  }
  return base32;
}

/**
 * Return whether a string is a base32 string.
 */
export function isBase32(str: string): boolean {
  if (str.length < 1) return true;
  if (str.length % 8 !== 0) return false;

  // Check contains only base 32 characters.
  for (const char of str.toUpperCase()) {
    if (!base32CharSet.has(char)) return false;
  }

  // Check if using = only at the end as padding character.
  if (str.includes("=") && str.match(/=[^=].*$/)) {
    return false;
  }

  return true;
}

const base32Alphabet = {
  0: "A",
  1: "B",
  2: "C",
  3: "D",
  4: "E",
  5: "F",
  6: "G",
  7: "H",
  8: "I",
  9: "J",
  10: "K",
  11: "L",
  12: "M",
  13: "N",
  14: "O",
  15: "P",
  16: "Q",
  17: "R",
  18: "S",
  19: "T",
  20: "U",
  21: "V",
  22: "W",
  23: "X",
  24: "Y",
  25: "Z",
  26: "2",
  27: "3",
  28: "4",
  29: "5",
  30: "6",
  31: "7",
  pad: "=",
};
export const base32Chars = Object.freeze(Object.values(base32Alphabet));
const base32CharSet = new Set();
for (const char of base32Chars) {
  base32CharSet.add(char);
}
