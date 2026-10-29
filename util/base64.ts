import { binaryToArrayBuffer, toBinary } from "./binary.ts";

const base64Chars =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const padChar = "=";

/**
 * Convert an array buffer to base64.
 */
export function toBase64(buffer: ArrayBuffer) {
  // We represent 6 bits per character by choosing a 64 character alphabet.
  // If not a multiple of 6 zero-pad. = is used at the end as the padding character. This is a 65th char.
  // Each 24-bits of input becomes 4 characters (6 * 4 = 24).
  // If there are fewer than 24-bits available at the end of the encoding the bits are padded on the right with 0.
  // Any of the padding bytes not part of the real data should be encoded as the padding character =
  if (buffer.byteLength === 0) {
    return "";
  }

  const charBitLength = 6;
  const numCharsPerQuantum = 4;

  const binaryStr = toBinary(buffer, false);

  // Split into 6-bit chunks.
  const chunks6Bit: string[] = [];
  for (let bitNum = 0; bitNum < binaryStr.length; bitNum += charBitLength) {
    // Final chunk may be less than 6 bits depending on our input. Right pad with 0s if so.
    const chunk = binaryStr.slice(bitNum, bitNum + charBitLength);
    const chunk6Bit = chunk.padEnd(charBitLength, "0");
    chunks6Bit.push(chunk6Bit);
  }

  // Split into 24-bit chunks. Base 64 always outputs in 24-bit/4 character chunks.
  const chunks24Bit: string[][] = [];
  for (let i = 0; i < chunks6Bit.length; i += numCharsPerQuantum) {
    const chunk24Bit = chunks6Bit.slice(i, i + numCharsPerQuantum);
    while (chunk24Bit.length < numCharsPerQuantum) {
      chunk24Bit.push("pad-bit");
    }
    chunks24Bit.push(chunk24Bit);
  }

  // Loop over our chunks and create our base 64 string.
  let base64 = "";
  for (const chunks6Bit of chunks24Bit) {
    for (const chunk6Bit of chunks6Bit) {
      if (chunk6Bit === "pad-bit") {
        base64 += padChar;
      } else {
        const chunk8BitsPadded = chunk6Bit.padStart(8, "0");
        const chunkBuffer = binaryToArrayBuffer(chunk8BitsPadded);
        const chunkValue = new Uint8Array(chunkBuffer)[0];
        const base64Char = base64Chars[chunkValue];
        base64 += base64Char;
      }
    }
  }
  return base64;
}
