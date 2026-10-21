// Spec: Digit
const codeDigits = 6;

/**
 * Calculate a HMAC based One-Time Password.
 *
 * https://www.rfc-editor.org/info/rfc4226
 *
 * @param key The key (secret) for the HMAC algorithm. K in the spec.
 * @param counter 8-byte counter value. C in the spec. We use bigint to avoid any floating point issues. HOTP spec
 * specifies 8 byte or 64 bit counters, and JavaScript numbers are only safe up to 53 bits (Number.MAX_SAFE_INTEGER).
 */
export async function hmacOneTimePassword(
  key: ArrayBuffer,
  counter: bigint,
): Promise<{
  hmacResult: ArrayBuffer;
  dynamicTruncateResult: ArrayBuffer;
  dynamicTruncateResultDecimal: number;
  code: string;
}> {
  validateArgs(key, counter);

  // HMAC-SHA-1 result is 20 bytes long. This will change when we later support other HMAC algorithms for TOTP.
  // Spec: HMAC-SHA-1(K, C)
  const hmacResult = await hmacSha1(key, counter);

  // Spec: Truncate(HMAC-SHA-1(K, C))
  const truncateResult = truncate(hmacResult);

  const codePadded = String(truncateResult.code).padStart(codeDigits, "0");

  return {
    hmacResult,
    dynamicTruncateResult: truncateResult.dynamicTruncateResult,
    dynamicTruncateResultDecimal: truncateResult.dynamicTruncateResultDecimal,
    code: codePadded,
  };
}

function validateArgs(key: ArrayBuffer, counter: bigint) {
  // Check key is at least 128 bits / 16 bytes.
  if (key.byteLength < 16) {
    throw new Error("Key is not long enough - it must be at least 16 bytes");
  }

  // Check counter fits in 64 bits.
  const maxCounter = 0xffff_ffff_ffff_ffffn; // Max 8 byte value
  if (counter < 0n || counter > maxCounter) {
    throw new Error("Counter is too long - it must fit in 8 bytes");
  }
}

async function hmacSha1(
  keyBytes: ArrayBuffer,
  counter: bigint,
): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    {
      name: "HMAC",
      hash: "SHA-1",
    },
    false,
    ["sign"],
  );

  // Spec requires counter to be 8 bytes, so allocate an 8 byte buffer.
  const counterBuffer = new ArrayBuffer(8);

  // Key and counter should be hashed high-order byte first, this means big endian - BE.
  new DataView(counterBuffer).setBigUint64(0, counter, false /* big endian */);

  const mac = await crypto.subtle.sign("HMAC", key, counterBuffer);
  return mac;
}

// Left for interest, but replaced Node HMAC use with Web Crypto Standard use.
// import { createHmac } from "node:crypto";
// function hmacSha1Node(key: ArrayBuffer, counter: bigint): ArrayBuffer {
//   // Convert our number to bytes.
//   // Spec requires counter to be 8 bytes, so allocate an 8 byte buffer.
//   const counterBytes = new ArrayBuffer(8);
//
//   // Key and counter should be hashed high-order byte first, this means big endian - BE.
//   new DataView(counterBytes).setBigUint64(0, counter, false);
//
//   // Create the HMAC.
//   return createHmac("sha1", new Uint8Array(key))
//     .update(new Uint8Array(counterBytes))
//     .digest().buffer;
// }

function truncate(hmacOutput: ArrayBuffer): {
  dynamicTruncateResult: ArrayBuffer;
  dynamicTruncateResultDecimal: number;
  code: number;
} {
  // Dynamic truncation.
  // Spec: Let Sbits = DT(HS)   //  DT, defined below, returns a 31-bit string
  const dynamicTruncateResult = dynamicTruncation(hmacOutput);

  // Compute HOTP value.
  // Specs: Let dynamicTruncateResultUint32 = StToNum(sBits)   // Convert S to a number in 0...2^{31}-1
  const dynamicTruncateResultUint32 = new DataView(
    dynamicTruncateResult,
  ).getUint32(0, false);

  // Spec: Return D = dynamicTruncateResultUint32 mod 10^Digit // D is a number in the range 0...10^{Digit}-1
  const code = dynamicTruncateResultUint32 % 10 ** codeDigits;
  return {
    dynamicTruncateResult,
    dynamicTruncateResultDecimal: dynamicTruncateResultUint32,
    code,
  };
}

// Truncate a 20-byte sequence into a dynamic 4-byte binary code.
export function dynamicTruncation(buffer: ArrayBuffer): ArrayBuffer {
  if (buffer.byteLength !== 20) {
    throw new Error(
      `Expected a buffer with 20 bytes, received one with ${buffer.byteLength} bytes`,
    );
  }

  // Spec: Let OffsetBits be the low-order 4 bits of the final byte
  const uint8Buffer = new Uint8Array(buffer);
  const finalByte = uint8Buffer[19];
  // Get the low-order 4 bits and convert them to a number (JS does this automatically after the bitwise op).
  // We know this won't leave to negative numbers because the sign bit will always be 0.
  // We also know offset must be 0 <= offset <= 15 as it's only 4 bits wide.
  const offset = finalByte & 0b0000_1111;

  /* Spec: Offset = StToNum(OffsetBits) // 0 <= OffSet <= 15
           Let P = String[OffSet]...String[OffSet+3]
     We have done it slightly differently but it should function correctly.
     We use offset + 4 as buffer.slice's end arg is not included. */
  // Get the 4 bytes from our buffer starting from offset.
  const offsetBuffer = buffer.slice(offset, offset + 4);

  // Spec: Return the Last 31 bits of P
  // Then we return the last 31 bits of these 4 bytes.
  const offsetMaskedBuffer = offsetBuffer.slice();
  const offsetMaskedUint8 = new Uint8Array(offsetMaskedBuffer);
  offsetMaskedUint8[0] &= 0b0111_1111; // Mask the first bit of the first byte.

  return offsetMaskedBuffer;
}
