import test from "node:test";
import assert from "node:assert/strict";
import { dynamicTruncation, hotp } from "./hotp.ts";
import { hexToArrayBuffer, toHex } from "../util/binary.ts";

const specTestSecret = hexToArrayBuffer(
  "3132333435363738393031323334353637383930",
);

// Appendix D - HOTP Algorithm: Test Values - https://www.rfc-editor.org/info/rfc4226/#page-32
test("spec tests - counter 0", async () => {
  const counter0Result = await hotp(specTestSecret, 0n);
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

test("spec tests - all counters", async () => {
  assert.equal((await hotp(specTestSecret, 0n)).code, "755224");
  assert.equal((await hotp(specTestSecret, 1n)).code, "287082");
  assert.equal((await hotp(specTestSecret, 2n)).code, "359152");
  assert.equal((await hotp(specTestSecret, 3n)).code, "969429");
  assert.equal((await hotp(specTestSecret, 4n)).code, "338314");
  assert.equal((await hotp(specTestSecret, 5n)).code, "254676");
  assert.equal((await hotp(specTestSecret, 6n)).code, "287922");
  assert.equal((await hotp(specTestSecret, 7n)).code, "162583");
  assert.equal((await hotp(specTestSecret, 8n)).code, "399871");
  assert.equal((await hotp(specTestSecret, 9n)).code, "520489");
});

test("codes are left padded if required", async () => {
  assert.equal((await hotp(specTestSecret, 30n)).code, "026920");
});

test("keys that are < 16 bytes are rejected", async () => {
  try {
    const buffer = new ArrayBuffer(15);
    const uint8Arr = new Uint8Array(buffer);
    for (let i = 0; i < uint8Arr.length; i++) {
      uint8Arr[i] = 0xff;
    }
    await hotp(uint8Arr.buffer, 5n);
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
    await hotp(specTestSecret, 0xffff_ffff_ffff_ffff_ffffn);
  } catch (e) {
    assert.equal(e.message, "Counter is too long - it must fit in 8 bytes");
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
