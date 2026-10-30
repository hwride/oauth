import test from "node:test";
import assert from "node:assert/strict";
import {
  fromBase16,
  fromBase32,
  fromBase32Hex,
  fromBase64,
  fromBase64Url,
  isBase16,
  isBase32,
  isBase64,
  isBase64Url,
  toBase16,
  toBase32,
  toBase32Hex,
  toBase64,
  toBase64Url,
} from "./base-encoding.ts";

const rfc4648TestVectors = [
  // The spec defines input as a string, so it will be the bits for the ASCII encoding of that string.
  {
    binaryAsAscii: "",
    base16: "",
    base32: "",
    base32hex: "",
    base64: "",
    base64Url: "",
  },
  {
    binaryAsAscii: "f",
    base16: "66",
    base32: "MY======",
    base32hex: "CO======",
    base64: "Zg==",
    base64Url: "Zg==",
  },
  {
    binaryAsAscii: "fo",
    base16: "666F",
    base32: "MZXQ====",
    base32hex: "CPNG====",
    base64: "Zm8=",
    base64Url: "Zm8=",
  },
  {
    binaryAsAscii: "foo",
    base16: "666F6F",
    base32: "MZXW6===",
    base32hex: "CPNMU===",
    base64: "Zm9v",
    base64Url: "Zm9v",
  },
  {
    binaryAsAscii: "foob",
    base16: "666F6F62",
    base32: "MZXW6YQ=",
    base32hex: "CPNMUOG=",
    base64: "Zm9vYg==",
    base64Url: "Zm9vYg==",
  },
  {
    binaryAsAscii: "fooba",
    base16: "666F6F6261",
    base32: "MZXW6YTB",
    base32hex: "CPNMUOJ1",
    base64: "Zm9vYmE=",
    base64Url: "Zm9vYmE=",
  },
  {
    binaryAsAscii: "foobar",
    base16: "666F6F626172",
    base32: "MZXW6YTBOI======",
    base32hex: "CPNMUOJ1E8======",
    base64: "Zm9vYmFy",
    base64Url: "Zm9vYmFy",
  },
] as const;

// bass 64
for (const { binaryAsAscii, base64 } of rfc4648TestVectors) {
  test(`toBase64 - input: ${binaryAsAscii}, expected: ${base64}`, () => {
    // Default TextEncoder encoding will encode the string as ASCII bits for those characters in the ASCII range.
    const buffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.strictEqual(toBase64(buffer), base64);
  });
}

for (const { binaryAsAscii, base64 } of rfc4648TestVectors) {
  test(`fromBase64 - input: ${base64}, expected: ${binaryAsAscii}`, () => {
    const expectedBuffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.deepStrictEqual(fromBase64(base64), expectedBuffer);
  });
}

test("fromBase64 - rejects non-zero pad bits", () => {
  assert.throws(() => fromBase64("Zh=="));
});

// Ensures our non-zero pad bits doesn't accidentally reject all 0s
test("fromBase64 - accepts zero-valued final symbol", () => {
  assert.deepStrictEqual(fromBase64("AA=="), new Uint8Array([0]).buffer);
});

test("fromBase64 - rejects zero bits without a complete byte", () => {
  assert.throws(() => fromBase64("A==="), /Invalid base64 encoding/);
});

test("isBase64 - valid", () => {
  assert.strictEqual(isBase64(""), true);
  assert.strictEqual(isBase64("Zm8="), true);
  assert.strictEqual(isBase64("Zm9v"), true);
});

test("isBase64 - invalid characters", () => {
  assert.strictEqual(isBase64("MMY´"), false);
  assert.strictEqual(isBase64("MMY@"), false);
});

// base64url
for (const { binaryAsAscii, base64Url } of rfc4648TestVectors) {
  test(`toBase64Url - input: ${binaryAsAscii}, expected: ${base64Url}`, () => {
    const buffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.strictEqual(toBase64Url(buffer), base64Url);
  });
}

for (const { binaryAsAscii, base64Url } of rfc4648TestVectors) {
  test(`fromBase64Url - input: ${base64Url}, expected: ${binaryAsAscii}`, () => {
    const expectedBuffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.deepStrictEqual(fromBase64Url(base64Url), expectedBuffer);
  });
}

test("toBase64Url - uses URL-safe alphabet", () => {
  const buffer = new Uint8Array([0xfb, 0xff, 0xff]).buffer;
  assert.strictEqual(toBase64Url(buffer), "-___");
});

test("fromBase64Url - uses URL-safe alphabet", () => {
  const expectedBuffer = new Uint8Array([0xfb, 0xff, 0xff]).buffer;
  assert.deepStrictEqual(fromBase64Url("-___"), expectedBuffer);
});

test("isBase64Url - valid", () => {
  assert.strictEqual(isBase64Url("-w=="), true);
  assert.strictEqual(isBase64Url("_w=="), true);
  assert.strictEqual(isBase64Url("-_8="), true);
});

test("isBase64Url - rejects standard Base64 characters", () => {
  assert.strictEqual(isBase64Url("+w=="), false);
  assert.strictEqual(isBase64Url("/w=="), false);
});

// bass 32
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

for (const { binaryAsAscii, base32hex } of rfc4648TestVectors) {
  test(`toBase32Hex - input: ${binaryAsAscii}, expected: ${base32hex}`, () => {
    const buffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.strictEqual(toBase32Hex(buffer), base32hex);
  });
}

for (const { binaryAsAscii, base32hex } of rfc4648TestVectors) {
  test(`fromBase32Hex - input: ${base32hex}, expected: ${binaryAsAscii}`, () => {
    const expectedBuffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.deepStrictEqual(fromBase32Hex(base32hex), expectedBuffer);
  });
}

test("fromBase32 - does not accept lowercase", () => {
  assert.throws(
    () => fromBase32(rfc4648TestVectors[4].base32.toLowerCase()),
    /Invalid base32 encoding/,
  );
});

test("fromBase32 - rejects non-zero pad bits", () => {
  assert.throws(() => fromBase32("MZ======"));
});

test("fromBase32 - accepts zero-valued final symbol", () => {
  assert.deepStrictEqual(fromBase32("AA======"), new Uint8Array([0]).buffer);
});

test("fromBase32 - rejects zero bits without a complete byte", () => {
  assert.throws(() => fromBase32("A======="), /Invalid base32 encoding/);
});

test("isBase32 - valid", () => {
  assert.strictEqual(isBase32(""), true);
  assert.strictEqual(isBase32("MY======"), true);
  assert.strictEqual(isBase32("MZXW6YTB"), true);
});

test("isBase32 - invalid characters", () => {
  assert.strictEqual(isBase32("MMMMMMY´"), false);
  assert.strictEqual(isBase32("MMMMMMY@"), false);
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

// bass 16
for (const { binaryAsAscii, base16 } of rfc4648TestVectors) {
  test(`toBase16 - input: ${binaryAsAscii}, expected: ${base16}`, () => {
    // Default TextEncoder encoding will encode the string as ASCII bits for those characters in the ASCII range.
    const buffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.strictEqual(toBase16(buffer), base16);
  });
}

for (const { binaryAsAscii, base16 } of rfc4648TestVectors) {
  test(`fromBase16 - input: ${base16}, expected: ${binaryAsAscii}`, () => {
    const expectedBuffer = new TextEncoder().encode(binaryAsAscii).buffer;
    assert.deepStrictEqual(fromBase16(base16), expectedBuffer);
  });
}

test("fromBase16 - rejects odd-length input", () => {
  assert.throws(() => fromBase16("ABC"));
});

test("isBase16 - valid", () => {
  assert.strictEqual(isBase16(""), true);
  assert.strictEqual(isBase16(rfc4648TestVectors[0].base16), true);
  assert.strictEqual(isBase16(rfc4648TestVectors[1].base16), true);
});

test("isBase16 - invalid characters", () => {
  assert.strictEqual(isBase16("MMY´"), false);
  assert.strictEqual(isBase16("MMY@"), false);
});
