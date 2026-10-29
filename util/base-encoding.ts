import { binaryToArrayBuffer, toBinary } from "./binary.ts";

/*
  RFC 4648: The Base16, Base32, and Base64 Data Encodings
  https://www.rfc-editor.org/info/rfc4648
 */

const base16Alphabet = "0123456789ABCDEF";
const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const base64Alphabet =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const padChar = "=";

/**
 * Convert an array buffer to base64.
 */
export function toBase64(buffer: ArrayBuffer) {
  return toBaseGeneric({
    buffer,
    alphabet: base64Alphabet,
    charBitLength: 6,
    numCharsPerGroup: 4,
  });
}

/**
 * Convert a base 64 string to an ArrayBuffer.
 */
export function fromBase64(base64Str: string): ArrayBuffer {
  return fromBaseGeneric({
    baseStr: base64Str,
    alphabet: base64Alphabet,
    charBitLength: 6,
  });
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
  return fromBaseGeneric({
    baseStr: base32Str,
    alphabet: base32Alphabet,
    charBitLength: 5,
  });
}

/**
 * Convert an array buffer to base16.
 */
export function toBase16(buffer: ArrayBuffer) {
  return toBaseGeneric({
    buffer,
    alphabet: base16Alphabet,
    charBitLength: 4,
    numCharsPerGroup: 1,
  });
}

/**
 * Convert a base 16 string to an ArrayBuffer.
 */
export function fromBase16(base16Str: string): ArrayBuffer {
  return fromBaseGeneric({
    baseStr: base16Str,
    alphabet: base16Alphabet,
    charBitLength: 4,
  });
}

export function fromBaseGeneric({
  baseStr,
  alphabet,
  charBitLength,
}: {
  baseStr: string;
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
}): ArrayBuffer {
  if (baseStr.length < 1) {
    return new ArrayBuffer();
  }

  // Reverse alphabet lookup
  const alphabetNumToChar: Record<string, string> = {};
  for (let i = 0; i < alphabet.length; i++) {
    alphabetNumToChar[alphabet[i]] = String(i);
  }

  let binaryStr = "";
  for (const char of baseStr) {
    // If we're at padding characters we are finished.
    if (char === "=") {
      break;
    }

    // Convert this character back to binary.
    const numVal = Number(alphabetNumToChar[char]);
    const charBinary = toBinary(new Uint8Array([numVal]).buffer);
    const charBinaryClampedToBits = charBinary.slice(
      -charBitLength,
      charBinary.length,
    );
    binaryStr += charBinaryClampedToBits;
  }

  // Make sure binary string is a multiple of 8 bits.
  // If not cut off the extras as they were padded 0s.
  const binaryStr8Remainder = binaryStr.length % 8;
  const binaryStrClamped =
    binaryStr8Remainder === 0
      ? binaryStr
      : binaryStr.slice(0, -binaryStr8Remainder);

  const buffer = binaryToArrayBuffer(binaryStrClamped);
  return buffer;
}

const base32CharsIncludingPadding = [...base32Alphabet].map((c) => c);
base32CharsIncludingPadding.push("=");
const base32CharSet = new Set();
for (const char of base32CharsIncludingPadding) {
  base32CharSet.add(char);
}

/**
 * Return whether a string is like a base32 string. It does not guarantee it is completely correct encoding.
 */
export function isBase64Like(str: string): boolean {
  return isBaseLike({
    str,
    alphabet: base64Alphabet,
    charBitLength: 6,
    numCharsPerGroup: 4,
  });
}

/**
 * Return whether a string is like a base32 string. It does not guarantee it is completely correct encoding.
 */
export function isBase32Like(str: string): boolean {
  return isBaseLike({
    str,
    alphabet: base32Alphabet,
    charBitLength: 5,
    numCharsPerGroup: 8,
  });
}

/**
 * Return whether a string is like a base32 string. It does not guarantee it is completely correct encoding.
 */
export function isBase16Like(str: string): boolean {
  return isBaseLike({
    str,
    alphabet: base16Alphabet,
    charBitLength: 4,
    numCharsPerGroup: 1,
  });
}

/**
 * Return whether a string is like a base X string. It does not guarantee it is completely correct encoding, but if it's
 * using the correct characters, of a correct looking length, and using padding characters correctly.
 */
export function isBaseLike({
  str,
  alphabet,
  numCharsPerGroup,
}: {
  str: string;
  alphabet: string;
  charBitLength: number;
  numCharsPerGroup: number;
}): boolean {
  // Empty strings are considered matching.
  if (str.length < 1) return true;

  // Check the string is multiple of expected character group size.
  if (str.length % numCharsPerGroup !== 0) return false;

  // Check contains only characters from this base's character set.
  let countPad = 0;
  for (const char of str) {
    if (char === "=") countPad++;
    else if (!alphabet.includes(char)) return false;
  }

  // Check if using = only at the end as padding character.
  if (str.includes("=") && str.match(/=[^=].*$/)) {
    return false;
  }

  return true;
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
