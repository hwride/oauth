import { binaryToArrayBuffer, toBinary } from "./binary.ts";

const base64Chars =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const padChar = "=";

/**
 * Convert an array buffer to base64.
 */
export function toBase64(buffer: ArrayBuffer) {
  return toBaseGeneric({
    buffer,
    charBitLength: 6,
    numCharsPerGroup: 4,
  });
}

export function toBaseGeneric({
  buffer,
  charBitLength,
  numCharsPerGroup,
}: {
  buffer: ArrayBuffer;
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
  // We represent 6 bits per character by choosing a 64 character alphabet.
  // If not a multiple of 6 zero-pad. = is used at the end as the padding character. This is a 65th char.
  // Each 24-bits of input becomes 4 characters (6 * 4 = 24).
  // If there are fewer than 24-bits available at the end of the encoding the bits are padded on the right with 0.
  // Any of the padding bytes not part of the real data should be encoded as the padding character =
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
        const base64Char = base64Chars[chunkValue];
        baseEncodedStr += base64Char;
      }
    }
  }
  return baseEncodedStr;
}
