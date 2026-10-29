import test from "node:test";
import assert from "node:assert/strict";
import { fromBase32, isBase32, toBase32 } from "./base32.ts";

const rfc4648Base32TestVectors = [
  // The spec defines input as a string, so it will be the bits for the ASCII
  // encoding of that string.
  { binaryAsAscii: "", base32: "" },
  { binaryAsAscii: "f", base32: "MY======" },
  { binaryAsAscii: "fo", base32: "MZXQ====" },
  { binaryAsAscii: "foo", base32: "MZXW6===" },
  { binaryAsAscii: "foob", base32: "MZXW6YQ=" },
  { binaryAsAscii: "fooba", base32: "MZXW6YTB" },
  { binaryAsAscii: "foobar", base32: "MZXW6YTBOI======" },
] as const;

for (const { binaryAsAscii, base32 } of rfc4648Base32TestVectors) {
  test(`toBase32 - input: ${binaryAsAscii}`, () => {
    // Default TextEncoder encoding will encode the string as ASCII bits for those characters in the ASCII range.
    const buffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.strictEqual(toBase32(buffer), base32);
  });
}

for (const { binaryAsAscii, base32 } of rfc4648Base32TestVectors) {
  test(`fromBase32 - input: ${base32}, expected: ${binaryAsAscii}`, () => {
    const expectedBuffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.deepStrictEqual(fromBase32(base32), expectedBuffer);
  });
}

test("fromBase32 - accepts lowercase", () => {
  const buffer = new TextEncoder().encode(
    rfc4648Base32TestVectors[4].binaryAsAscii,
  ).buffer;
  assert.deepStrictEqual(
    fromBase32(rfc4648Base32TestVectors[4].base32),
    buffer,
  );
});

test("isBase32 - valid", () => {
  assert.strictEqual(isBase32(""), true);
  assert.strictEqual(isBase32("MY======"), true);
  assert.strictEqual(isBase32("MZXW6YTB"), true);
});

test("isBase32 - accept lowercase", () => {
  assert.strictEqual(isBase32(""), true);
  assert.strictEqual(isBase32("my======"), true);
  assert.strictEqual(isBase32("mzXw6ytb"), true);
});

test("isBase32 - invalid characters", () => {
  assert.strictEqual(isBase32("1"), false);
  assert.strictEqual(isBase32("MY1=="), false);
  assert.strictEqual(isBase32("MY´"), false);
  assert.strictEqual(isBase32("MY@"), false);
});

test("isBase32 - padding must only be at the end", () => {
  assert.strictEqual(isBase32("=ABC"), false);
  assert.strictEqual(isBase32("A=BC"), false);
  assert.strictEqual(isBase32("M=Y====="), false);
});

test("isBase32 - invalid padding", () => {
  assert.strictEqual(isBase32("="), false);
  assert.strictEqual(isBase32("A="), false);
  assert.strictEqual(isBase32("MZXW6YTB="), false);
  assert.strictEqual(isBase32("MY======="), false);
});

test("isBase32 - invalid padding lengths", () => {
  assert.strictEqual(isBase32("A======="), false);
  assert.strictEqual(isBase32("AAA====="), false);
  assert.strictEqual(isBase32("========"), false);
});

test("isBase32 - invalid unpadded lengths", () => {
  assert.strictEqual(isBase32("A"), false);
  assert.strictEqual(isBase32("ABC"), false);
});
