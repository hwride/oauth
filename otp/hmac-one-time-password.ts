import { binaryToArrayBuffer, toBinary } from "../util/binary.ts";

export type HotpOptions = {
  /** The key (secret) for the HMAC algorithm. K in the spec. */
  key: ArrayBuffer;
  /**
   * 8-byte counter value. C in the spec. We use bigint to avoid any floating point issues.
   * HOTP spec specifies 8 byte or 64 bit counters, and JavaScript numbers are only safe up to 53 bits (Number.MAX_SAFE_INTEGER).
   */
  counter: bigint;
  /** The length of the OTP. Clamped between 6 and 10 for numeric codes, and between 4 and 6 for alphanumeric codes. */
  codeLength?: number;
  /** Whether to generate a number or alphanumeric OTP. */
  codeType?: CodeType;
  /** What hash algorithm to use. */
  hashAlgorithm?: HashAlgorithm;
};
export const supportedHashAlgorithms = ["SHA-1", "SHA-256", "SHA-512"] as const;
export type HashAlgorithm = (typeof supportedHashAlgorithms)[number];
export type CodeType = "numeric" | "alphanumeric";

/**
 * Calculate a HMAC based One-Time Password.
 *
 * https://www.rfc-editor.org/info/rfc4226
 */
export async function hmacOneTimePassword(options: HotpOptions): Promise<{
  hmacResult: ArrayBuffer;
  dynamicTruncateResult: ArrayBuffer;
  dynamicTruncateResultDecimal: number;
  code: string;
}> {
  const { key, counter, codeType, codeLength, hashAlgorithm } =
    validateArgs(options);

  // Depending on the hash algorithm this buffer will be different lengths.
  // Spec: HMAC-SHA-1(K, C)
  const macBuffer = await hmac(key, counter, hashAlgorithm);

  // Spec: Truncate(HMAC-SHA-1(K, C))
  // Dynamic truncation.
  // Spec: Let Sbits = DT(HS)   //  DT, defined below, returns a 31-bit string
  const dynamicTruncateResult = dynamicTruncation(macBuffer);

  // Compute HOTP value.
  // Spec: Let Snum = StToNum(sBits)   // Convert S to a number in 0...2^{31}-1
  const dynamicTruncateResultUint32 = new DataView(
    dynamicTruncateResult,
  ).getUint32(0, false);

  let code: string;
  // https://www.rfc-editor.org/info/rfc4226/#appendix-E.2
  // Note the spec doesn't actually propose a way to implement this though.
  if (codeType === "alphanumeric") {
    code = generateAlphanumericCode(dynamicTruncateResult, codeLength);
  } else {
    code = generateNumericCode(dynamicTruncateResultUint32, codeLength);
  }

  return {
    hmacResult: macBuffer,
    dynamicTruncateResult,
    dynamicTruncateResultDecimal: dynamicTruncateResultUint32,
    code,
  };
}

function generateAlphanumericCode(
  dynamicTruncateResult: ArrayBuffer,
  codeLength: number,
): string {
  // Our dynamicTruncateResult is 32-bits
  // ASCII numbers = 48-57, excluding 0 and 1 (8 values)
  // ASCII uppercase alphabet = 65-90, excluding I and O (24 values)
  // Total = 32 values
  // The total number of values that can be represented by 5 bits is 32 (0-31)
  // This means we can take 5-bit chunks from our 31 meaningful bits and get a code up to 6 characters long.
  let code = "";
  // We slice the first bit as it's always 0 so not providing randomness, because it was masked off.
  // This leaves us with 31 meaningful bits.
  // But because we're doing 5-bit chunks for 6 letters, we only use 30 of those bits (6 * 5 = 30).
  const binaryString = toBinary(dynamicTruncateResult, false).slice(1);
  const textDecoder = new TextDecoder();

  // Generate a list of valid ASCII codes.
  // We exclude potentially confusing codes - 0, 1, I, O
  // Chose to exclude codes so we leave a total of 32 characters in the remaining set, matching spec suggestion.
  const excludedAsciiCodes = [48, 49, 73, 79];
  const validAsciiCodes = [];
  for (let asciiCode = 48; asciiCode <= 57; asciiCode++) {
    if (!excludedAsciiCodes.includes(asciiCode)) {
      validAsciiCodes.push(asciiCode);
    }
  }
  for (let asciiCode = 65; asciiCode <= 90; asciiCode++) {
    if (!excludedAsciiCodes.includes(asciiCode)) {
      validAsciiCodes.push(asciiCode);
    }
  }

  for (let i = 0; i < codeLength; i += 1) {
    const binaryStringPart = binaryString.slice(i * 5, i * 5 + 5);
    const partBuffer = binaryToArrayBuffer(binaryStringPart);
    const partUint8 = new Uint8Array(partBuffer);
    const partNumber = partUint8[0];
    const asciiCode = validAsciiCodes[partNumber % validAsciiCodes.length];
    const partBufferClamped = new Uint8Array([asciiCode]);
    const letter = textDecoder.decode(partBufferClamped);
    code += letter;
  }

  return code.slice(0, codeLength);
}

function generateNumericCode(
  dynamicTruncateResultUint32: number,
  codeLength: number,
): string {
  // Spec: Return D = Snum mod 10^Digit // D is a number in the range 0...10^{Digit}-1
  // % is technically signed remainder not mod, but they function they same when you know
  // both the dividend (left value) is > -1 and the divisor (right value) is > 0.
  const codeNumericNotPadded = dynamicTruncateResultUint32 % 10 ** codeLength;
  return String(codeNumericNotPadded).padStart(codeLength, "0");
}

function validateArgs(options: HotpOptions): Required<HotpOptions> {
  const validatedOptions: Required<HotpOptions> = {
    ...options,
    codeLength: options.codeLength ?? 6,
    codeType: options.codeType ?? "numeric",
    hashAlgorithm: options.hashAlgorithm ?? "SHA-1",
  };

  // Check key is at least 128 bits / 16 bytes.
  if (options.key.byteLength < 16) {
    throw new Error("Key is not long enough - it must be at least 16 bytes");
  }

  // Check counter fits in 64 bits.
  const maxCounter = 0xffff_ffff_ffff_ffffn; // Max 8 byte value
  if (options.counter < 0n || options.counter > maxCounter) {
    throw new Error("Counter is too long - it must fit in 8 bytes");
  }

  // Check digits.
  if (!Number.isInteger(validatedOptions.codeLength)) {
    throw new Error("Digits is not an integer");
  }

  // If you use > 10 digits it's just 0 padded anyway, as the maximum
  // 32-bit unsigned int is 4294967295 which is 10 digits.
  if (validatedOptions.codeType === "numeric") {
    validatedOptions.codeLength = Math.min(
      10,
      Math.max(6, validatedOptions.codeLength),
    );
  }
  // codeType - alphanumeric
  else {
    validatedOptions.codeLength = Math.min(
      6,
      Math.max(4, validatedOptions.codeLength),
    );
  }

  // Check hash algorithm.
  if (!supportedHashAlgorithms.includes(validatedOptions.hashAlgorithm)) {
    throw new Error(
      `Unsupported hash algorithm. Supported: ${supportedHashAlgorithms}`,
    );
  }

  return validatedOptions;
}

async function hmac(
  keyBytes: ArrayBuffer,
  counter: bigint,
  hash: HashAlgorithm,
): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    {
      name: "HMAC",
      hash,
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

/**
 * Truncate our HMAC result into a dynamic 4-byte binary code.
 */
export function dynamicTruncation(buffer: ArrayBuffer): ArrayBuffer {
  // Spec: Let OffsetBits be the low-order 4 bits of the final byte
  const uint8Buffer = new Uint8Array(buffer);
  const finalByte = uint8Buffer[buffer.byteLength - 1];
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
