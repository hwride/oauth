import test from "node:test";
import assert from "node:assert/strict";
import {
  fromBase32,
  isBase32,
  toBase16,
  toBase32,
  toBase64,
} from "./base-encoding.ts";

const rfc4648TestVectors = [
  // The spec defines input as a string, so it will be the bits for the ASCII encoding of that string.
  { binaryAsAscii: "", base16: "", base32: "", base64: "" },
  { binaryAsAscii: "f", base16: "66", base32: "MY======", base64: "Zg==" },
  {
    binaryAsAscii: "fo",
    base16: "666F",
    base32: "MZXQ====",
    base64: "Zm8=",
  },
  {
    binaryAsAscii: "foo",
    base16: "666F6F",
    base32: "MZXW6===",
    base64: "Zm9v",
  },
  {
    binaryAsAscii: "foob",
    base16: "666F6F62",
    base32: "MZXW6YQ=",
    base64: "Zm9vYg==",
  },
  {
    binaryAsAscii: "fooba",
    base16: "666F6F6261",
    base32: "MZXW6YTB",
    base64: "Zm9vYmE=",
  },
  {
    binaryAsAscii: "foobar",
    base16: "666F6F626172",
    base32: "MZXW6YTBOI======",
    base64: "Zm9vYmFy",
  },
] as const;

for (const { binaryAsAscii, base64 } of rfc4648TestVectors) {
  test(`toBase64 - input: ${binaryAsAscii}, expected: ${base64}`, () => {
    // Default TextEncoder encoding will encode the string as ASCII bits for those characters in the ASCII range.
    const buffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.strictEqual(toBase64(buffer), base64);
  });
}

for (const { binaryAsAscii, base32 } of rfc4648TestVectors) {
  test(`toBase32 - input: ${binaryAsAscii}, expected: ${base32}`, () => {
    // Default TextEncoder encoding will encode the string as ASCII bits for those characters in the ASCII range.
    const buffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.strictEqual(toBase32(buffer), base32);
  });
}

for (const { binaryAsAscii, base32 } of rfc4648TestVectors) {
  test(`fromBase32 - input: ${base32}, expected: ${binaryAsAscii}`, () => {
    const expectedBuffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.deepStrictEqual(fromBase32(base32), expectedBuffer);
  });
}

for (const { binaryAsAscii, base16 } of rfc4648TestVectors) {
  test(`toBase16 - input: ${binaryAsAscii}, expected: ${base16}`, () => {
    // Default TextEncoder encoding will encode the string as ASCII bits for those characters in the ASCII range.
    const buffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.strictEqual(toBase16(buffer), base16);
  });
}

test("fromBase32 - accepts lowercase", () => {
  const buffer = new TextEncoder().encode(
    rfc4648TestVectors[4].binaryAsAscii,
  ).buffer;
  assert.deepStrictEqual(fromBase32(rfc4648TestVectors[4].base32), buffer);
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
