import test from "node:test";
import assert from "node:assert/strict";
import {
  dynamicTruncation,
  hmacOneTimePassword,
} from "./hmac-one-time-password.ts";
import { toHex } from "../util/binary.ts";

const textEncoder = new TextEncoder();
const specTestSecret = textEncoder.encode("12345678901234567890").buffer;

// Appendix D - HOTP Algorithm: Test Values - https://www.rfc-editor.org/info/rfc4226/#page-32
test("spec tests - counter 0", async () => {
  const counter0Result = await hmacOneTimePassword({
    key: specTestSecret,
    counter: 0n,
  });
  assert.deepEqual(
    {
      hmacResultHex: toHex(counter0Result.hmacResult, false),
      dynamicTruncateResultHex: toHex(
        counter0Result.dynamicTruncateResult,
        false,
      ),
      dynamicTruncateResultDecimal: counter0Result.dynamicTruncateResultDecimal,
      code: counter0Result.code,
    },
    {
      hmacResultHex: "cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
      dynamicTruncateResultHex: "4c93cf18",
      dynamicTruncateResultDecimal: 1284755224,
      code: "755224",
    },
  );
});

test("spec tests - all counters (6 digits)", async () => {
  assert.equal(
    (await hmacOneTimePassword({ key: specTestSecret, counter: 0n })).code,
    "755224",
  );
  assert.equal(
    (await hmacOneTimePassword({ key: specTestSecret, counter: 1n })).code,
    "287082",
  );
  assert.equal(
    (await hmacOneTimePassword({ key: specTestSecret, counter: 2n })).code,
    "359152",
  );
  assert.equal(
    (await hmacOneTimePassword({ key: specTestSecret, counter: 3n })).code,
    "969429",
  );
  assert.equal(
    (await hmacOneTimePassword({ key: specTestSecret, counter: 4n })).code,
    "338314",
  );
  assert.equal(
    (await hmacOneTimePassword({ key: specTestSecret, counter: 5n })).code,
    "254676",
  );
  assert.equal(
    (await hmacOneTimePassword({ key: specTestSecret, counter: 6n })).code,
    "287922",
  );
  assert.equal(
    (await hmacOneTimePassword({ key: specTestSecret, counter: 7n })).code,
    "162583",
  );
  assert.equal(
    (await hmacOneTimePassword({ key: specTestSecret, counter: 8n })).code,
    "399871",
  );
  assert.equal(
    (await hmacOneTimePassword({ key: specTestSecret, counter: 9n })).code,
    "520489",
  );
});

test("codes are left padded if required", async () => {
  assert.equal(
    (await hmacOneTimePassword({ key: specTestSecret, counter: 30n })).code,
    "026920",
  );
});

test("codes > 6 digits", async () => {
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 0n,
        codeLength: 7,
      })
    ).code,
    "4755224",
  );
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 1n,
        codeLength: 8,
      })
    ).code,
    "94287082",
  );
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 1n,
        codeLength: 9,
      })
    ).code,
    "094287082",
  );
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 2n,
        codeLength: 10,
      })
    ).code,
    "0137359152",
  );
});

test("codes < 6 digits or > 10 digits is clamped", async () => {
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 0n,
        codeLength: 1,
      })
    ).code,
    "755224",
  );
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 0n,
        codeLength: 2,
      })
    ).code,
    "755224",
  );
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 0n,
        codeLength: 15,
      })
    ).code,
    "1284755224",
  );
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 0n,
        codeLength: 100,
      })
    ).code,
    "1284755224",
  );
});

test("alphanumeric codes - 6 digits", async () => {
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 0n,
        codeType: "alphanumeric",
      })
    ).code,
    "M6MTWE",
  );
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 1n,
        codeType: "alphanumeric",
      })
    ).code,
    "JBTHVP",
  );
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 2n,
        codeType: "alphanumeric",
      })
    ).code,
    "43HXWS",
  );
});

const totpSpecTestSecrets = Object.freeze({
  sha1: specTestSecret,
  sha256: textEncoder.encode("12345678901234567890123456789012").buffer,
  sha512: textEncoder.encode(
    "1234567890123456789012345678901234567890123456789012345678901234",
  ).buffer,
});

const totpSpecTestValues = [
  {
    counter: 0x0000000000000001n,
    sha1: "94287082",
    sha256: "46119246",
    sha512: "90693936",
  },
  {
    counter: 0x00000000023523ecn,
    sha1: "07081804",
    sha256: "68084774",
    sha512: "25091201",
  },
  {
    counter: 0x00000000023523edn,
    sha1: "14050471",
    sha256: "67062674",
    sha512: "99943326",
  },
  {
    counter: 0x000000000273ef07n,
    sha1: "89005924",
    sha256: "91819424",
    sha512: "93441116",
  },
  {
    counter: 0x0000000003f940aan,
    sha1: "69279037",
    sha256: "90698825",
    sha512: "38618901",
  },
  {
    counter: 0x0000000027bc86aan,
    sha1: "65353130",
    sha256: "77737706",
    sha512: "47863826",
  },
] as const;

test("TOTP (RFC 6238) spec tests - SHA-1", async () => {
  for (const testValue of totpSpecTestValues) {
    assert.equal(
      (
        await hmacOneTimePassword({
          key: totpSpecTestSecrets.sha1,
          counter: testValue.counter,
          codeLength: 8,
          hashAlgorithm: "SHA-1",
        })
      ).code,
      testValue.sha1,
    );
  }
});

test("TOTP (RFC 6238) spec tests - SHA-256", async () => {
  for (const testValue of totpSpecTestValues) {
    assert.equal(
      (
        await hmacOneTimePassword({
          key: totpSpecTestSecrets.sha256,
          counter: testValue.counter,
          codeLength: 8,
          hashAlgorithm: "SHA-256",
        })
      ).code,
      testValue.sha256,
    );
  }
});

test("TOTP (RFC 6238) spec tests - SHA-512", async () => {
  for (const testValue of totpSpecTestValues) {
    assert.equal(
      (
        await hmacOneTimePassword({
          key: totpSpecTestSecrets.sha512,
          counter: testValue.counter,
          codeLength: 8,
          hashAlgorithm: "SHA-512",
        })
      ).code,
      testValue.sha512,
    );
  }
});

test("alphanumeric codes with a length of < 4 or > 6 or clamped ", async () => {
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 0n,
        codeType: "alphanumeric",
        codeLength: 1,
      })
    ).code,
    "M6MT",
  );
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 0n,
        codeType: "alphanumeric",
        codeLength: 7,
      })
    ).code,
    "M6MTWE",
  );
  assert.equal(
    (
      await hmacOneTimePassword({
        key: specTestSecret,
        counter: 1n,
        codeType: "alphanumeric",
        codeLength: 10,
      })
    ).code,
    "JBTHVP",
  );
});

test("keys that are < 16 bytes are rejected", async () => {
  try {
    const buffer = new ArrayBuffer(15);
    const uint8Arr = new Uint8Array(buffer);
    for (let i = 0; i < uint8Arr.length; i++) {
      uint8Arr[i] = 0xff;
    }
    await hmacOneTimePassword({ key: uint8Arr.buffer, counter: 5n });
  } catch (e) {
    assert.equal(
      e.message,
      "Key is not long enough - it must be at least 16 bytes",
    );
    return;
  }
  assert.equal(true, false);
});

test("counters > 8 bytes are rejected", async () => {
  try {
    await hmacOneTimePassword({
      key: specTestSecret,
      counter: 0xffff_ffff_ffff_ffff_ffffn,
    });
  } catch (e) {
    assert.equal(e.message, "Counter is too long - it must fit in 8 bytes");
    return;
  }
  assert.equal(true, false);
});

test("NaN digits is rejected", async () => {
  try {
    await hmacOneTimePassword({
      key: specTestSecret,
      counter: 1n,
      codeLength: NaN,
    });
  } catch (e) {
    assert.equal(e.message, "Digits is not an integer");
    return;
  }
  assert.equal(true, false);
});

test("dynamicTruncation returns 4 bytes from the calculated offset", () => {
  // We expect dynamicTruncation to return 4 bytes, starting at offset.
  // Offset is calculated from the final 4 bits in the final byte.
  // Note this test has all offset bytes with 0 as the MSB, so it doesn't test masking.

  // Here the final byte ends in 1111, so it should have 15 for its offset.
  dynamicTruncationTestHelper(
    [
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
      0b1111_1111,
    ],
    [15, 16, 17, 18],
  );

  // Here the final byte ends in 0000, so it should have 0 for its offset.
  dynamicTruncationTestHelper(
    [
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
      0b1111_0000,
    ],
    [0, 1, 2, 3],
  );

  // Here the final byte ends in 0101, so it should have 5 for its offset.
  dynamicTruncationTestHelper(
    [
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
      0b1111_0101,
    ],
    [5, 6, 7, 8],
  );
});

test("dynamicTruncation masks result", () => {
  dynamicTruncationTestHelper(
    [
      // Here the first offset byte has a 1 for its MSB.
      0b1111_1111, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
      18, 0b1111_0000,
    ],
    // So we check that's masked correctly.
    [0b0111_1111, 1, 2, 3],
  );
});

// https://www.rfc-editor.org/info/rfc4226/#section-5.4
test("dynamicTruncation spec test - section 5.4", () => {
  dynamicTruncationTestHelper(
    [
      0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef,
      0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a,
    ],
    [0x50, 0xef, 0x7f, 0x19],
  );
});

// Appendix D - HOTP Algorithm: Test Values - https://www.rfc-editor.org/info/rfc4226/#page-32
test("dynamicTruncation spec test - appendix D - counter 1", () => {
  // https://www.rfc-editor.org/info/rfc4226/#section-5.4
  dynamicTruncationTestHelper(
    [
      0xcc, 0x93, 0xcf, 0x18, 0x50, 0x8d, 0x94, 0x93, 0x4c, 0x64, 0xb6, 0x5d,
      0x8b, 0xa7, 0x66, 0x7f, 0xb7, 0xcd, 0xe4, 0xb0,
    ],
    [0x4c, 0x93, 0xcf, 0x18],
  );
});

function dynamicTruncationTestHelper(
  inputBytes: Array<number>,
  expectedBytes: Array<number>,
) {
  assert.deepEqual(
    dynamicTruncation(new Uint8Array(inputBytes).buffer),
    new Uint8Array(expectedBytes).buffer,
  );
}
