import { binaryToArrayBuffer, toBinary } from "./binary.ts";

/*
  RFC 4648: The Base16, Base32, and Base64 Data Encodings
  https://www.rfc-editor.org/info/rfc4648
 */

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const base32AlphabetObject = Object.freeze({
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
});
export const base32Chars = Object.freeze(Object.values(base32AlphabetObject));
const base32CharSet = new Set();
for (const char of base32Chars) {
  base32CharSet.add(char);
}
const base32AlphabetReverse: Record<string, string> = {};
for (const [num, char] of Object.entries(base32AlphabetObject)) {
  base32AlphabetReverse[char] = num;
}

/**
 * Convert an array buffer to base32.
 */
export function toBase32(buffer: ArrayBuffer) {
  return toBaseGeneric({
    buffer,
    alphabet: base32Alphabet,
    charBitLength: 5,
    numCharsPerGroup: 8,
  });
}

/**
 * Convert a base 32 string to an ArrayBuffer.
 */
export function fromBase32(base32Str: string): ArrayBuffer {
  if (!isBase32(base32Str)) {
    throw new Error("Not a base 32 string");
  }
  if (base32Str.length < 1) {
    return new ArrayBuffer();
  }
  const base32StrUpper = base32Str.toUpperCase();

  let binaryStr = "";
  for (const char of base32StrUpper) {
    // If we're at padding characters we are finished.
    if (char === "=") {
      break;
    }

    // Convert this character back to binary.
    const numVal = Number(base32AlphabetReverse[char]);
    const binaryStrChunk = toBinary(new Uint8Array([numVal]).buffer);
    const binaryStrChunk5bits = binaryStrChunk.slice(-5, binaryStrChunk.length);
    binaryStr += binaryStrChunk5bits;
  }

  // Make sure binary string is a multiple of 8 bits.
  const binaryStr8Remainder = binaryStr.length % 8;
  const binaryStrClamped =
    binaryStr8Remainder === 0
      ? binaryStr
      : binaryStr.slice(0, -binaryStr8Remainder);

  const buffer = binaryToArrayBuffer(binaryStrClamped);
  return buffer;
}

/**
 * Return whether a string is a base32 string.
 */
export function isBase32(str: string): boolean {
  if (str.length < 1) return true;
  if (str.length % 8 !== 0) return false;

  // Check contains only base 32 characters.
  let countPad = 0;
  for (const char of str.toUpperCase()) {
    if (!base32CharSet.has(char)) return false;
    if (char === "=") countPad++;
  }

  // There can only be this number of padding characters.
  if (![0, 1, 3, 4, 6].includes(countPad)) {
    return false;
  }

  // Check if using = only at the end as padding character.
  if (str.includes("=") && str.match(/=[^=].*$/)) {
    return false;
  }

  return true;
}

const base64Chars =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const padChar = "=";

/**
 * Convert an array buffer to base64.
 */
export function toBase64(buffer: ArrayBuffer) {
  return toBaseGeneric({
    buffer,
    alphabet: base64Chars,
    charBitLength: 6,
    numCharsPerGroup: 4,
  });
}

export function toBaseGeneric({
  buffer,
  alphabet,
  charBitLength,
  numCharsPerGroup,
}: {
  buffer: ArrayBuffer;
  /**
   * A string containing the alphabet to use for this base encoding. Index in the string should equal the character
   * to use at that value.
   */
  alphabet: string;
  /**
   * This should match the number of bits required to represent numbers in that base. E.g.
   *   base 64 = 6 bits
   *   base 32 = 5 bits
   *   base 16 = 4 bits
   */
  charBitLength: number;
  /**
   * How many base characters are required to make up a grouping as used in the case algorithm.
   * For example base 32 uses 40-bit groups, and 5-bits chars, 40/5 = 8 chars per group.
   */
  numCharsPerGroup: number;
}) {
  // We represent charBitLength bits per character by choosing a base X character alphabet.
  // If not a multiple of charBitLength we zero-pad with =, this is an extra character.
  // We always process in groups of numCharsPerGroup length. If there are fewer than bits in the source buffer to
  // fulfill charBitLength * numCharsPerGroup for the final group, we right pad the final character with 0s.
  // Any further bits needed to fill the final group are encoded as the pad bit character.
  if (buffer.byteLength === 0) {
    return "";
  }

  const binaryStr = toBinary(buffer, false);

  // Split into chunks the size of each character.
  const charChunks: string[] = [];
  for (let bitNum = 0; bitNum < binaryStr.length; bitNum += charBitLength) {
    // Final chunk may be less than 6 bits depending on our input. Right pad with 0s if so.
    const chunk = binaryStr.slice(bitNum, bitNum + charBitLength);
    const chunk6Bit = chunk.padEnd(charBitLength, "0");
    charChunks.push(chunk6Bit);
  }

  // Split into our chunk groups.
  const charChunksGrouped: string[][] = [];
  for (let i = 0; i < charChunks.length; i += numCharsPerGroup) {
    const chunkGroup = charChunks.slice(i, i + numCharsPerGroup);
    // Ensure if char chunks wasn't long enough, our group is filled up with pad bits.
    while (chunkGroup.length < numCharsPerGroup) {
      chunkGroup.push("pad-bit");
    }
    charChunksGrouped.push(chunkGroup);
  }

  // Loop over our chunks and create our base X string.
  let baseEncodedStr = "";
  for (const charChunkGroup of charChunksGrouped) {
    for (const charChunk of charChunkGroup) {
      if (charChunk === "pad-bit") {
        baseEncodedStr += padChar;
      } else {
        const chunk8BitsPadded = charChunk.padStart(8, "0");
        const chunkBuffer = binaryToArrayBuffer(chunk8BitsPadded);
        const chunkValue = new Uint8Array(chunkBuffer)[0];
        const baseXChar = alphabet[chunkValue];
        baseEncodedStr += baseXChar;
      }
    }
  }
  return baseEncodedStr;
}
