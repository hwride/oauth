import { createHmac } from "node:crypto";

/**
 * Calculate a HMAC based One-Time Password.
 *
 * https://www.rfc-editor.org/info/rfc4226
 *
 * @param key The key (secret) for the HMAC algorithm. K in the spec.
 * @param counter 8-byte counter value. C in the spec. We use bigint to avoid any floating point issues. HOTP spec
 * specifies 8 byte or 64 bit counters, and JavaScript numbers are only safe up to 53 bits (Number.MAX_SAFE_INTEGER).
 */
export function hotp(key: Uint8Array, counter: bigint): string {
  /*
    K          = shared secret between client and server
    C          = 8-byte counter
    Digit      = number of digits in a HOTP value
    HOTP(K, C) = Truncate(HMAC-SHA-1(K, C))
   */

  // HMAC-SHA-1 result is 20 bytes long. This will change when we later support other HMAC algorithms for TOTP.
  const hmacVal = hmacSha1(key, counter);
  const truncated = truncate(hmacVal);
  return truncated;
}

function hmacSha1(key: Uint8Array, counter: bigint): Buffer {
  // Convert our number to bytes.
  // Spec requires counter to be 8 bytes, so allocate an 8 byte buffer.
  const counterBytes = Buffer.alloc(8);

  // UInt - unsigned int - because counters cannot be negative.
  // 64 bits = 8 bytes
  // Key and counter should be hashed high-order byte first, this means big endian - BE.
  counterBytes.writeBigUInt64BE(counter);

  // Create the HMAC.
  return createHmac("sha1", key).update(counterBytes).digest();
}

function truncate(hmacOutput: Buffer): string {
  // Dynamic truncation.
  const sBits = dynamicTruncation(hmacOutput);

  // Computer HOTP value.

  // Temp code
  const number = hmacOutput.readUInt32BE(0);
  const numStr = String(number);
  return numStr.slice(0, 6).padEnd(6, "0");
}

// Truncate a 20-byte sequence into a dynamic 4-byte binary code.
export function dynamicTruncation(bytes: Buffer): Buffer {
  // Spec: Let OffsetBits be the low-order 4 bits of the final byte
  const finalByte = bytes[19];
  // Get the low-order 4 bits.
  const offsetBits = finalByte & 0b11110000;

  return Buffer.from([offsetBits]);
}
