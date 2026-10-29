import test from "node:test";
import assert from "node:assert/strict";
import { isBase32, toBase32 } from "./base32.ts";

const rfc4648Base32TestVectors = [
  // The spec defines input as a string, so it will be the bits for the ASCII
  // encoding of that string.
  { input: "", expectedBase32: "" },
  { input: "f", expectedBase32: "MY======" },
  { input: "fo", expectedBase32: "MZXQ====" },
  { input: "foo", expectedBase32: "MZXW6===" },
  { input: "foob", expectedBase32: "MZXW6YQ=" },
  { input: "fooba", expectedBase32: "MZXW6YTB" },
  { input: "foobar", expectedBase32: "MZXW6YTBOI======" },
] as const;

for (const { input, expectedBase32 } of rfc4648Base32TestVectors) {
  test(`toBase32 RFC 4648 test vectors - input: ${input}`, () => {
    // Default TextEncoder encoding will encode the string as ASCII bits for those characters in the ASCII range.
    const buffer = new TextEncoder().encode(input).buffer;
    assert.strictEqual(toBase32(buffer), expectedBase32);
  });
}

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

test("isBase32 - invalid unpadded lengths", () => {
  assert.strictEqual(isBase32("A"), false);
  assert.strictEqual(isBase32("ABC"), false);
});
