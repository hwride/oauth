import test from "node:test";
import assert from "node:assert/strict";
import {
  hexToArrayBuffer,
  toHex,
  toBinary,
  binaryToArrayBuffer,
} from "../util/binary.ts";

test("toBinary and toHex - 1 byte", async () => {
  const buffer1Byte = new ArrayBuffer(1);
  new DataView(buffer1Byte).setUint8(0, 0b1111_0000);
  assert.strictEqual(toBinary(buffer1Byte), "11110000");
  assert.strictEqual(toHex(buffer1Byte), "f0");

  assert.deepEqual(hexToArrayBuffer("f0"), buffer1Byte);
  assert.deepEqual(binaryToArrayBuffer("11110000"), buffer1Byte);
});

test("toBinary and toHex - 2 bytes", async () => {
  const buffer2Bytes = new ArrayBuffer(2);
  new DataView(buffer2Bytes).setUint8(0, 0b11110000);
  new DataView(buffer2Bytes).setUint8(1, 0b00001111);
  assert.strictEqual(toBinary(buffer2Bytes), "11110000 00001111");
  assert.strictEqual(toHex(buffer2Bytes), "f0 0f");

  assert.deepEqual(hexToArrayBuffer("f0 0f"), buffer2Bytes);
  assert.deepEqual(binaryToArrayBuffer("1111000000001111"), buffer2Bytes);
});

test("toBinary and toHex - 4 bytes", async () => {
  const buffer4Bytes = new ArrayBuffer(4);
  new DataView(buffer4Bytes).setUint32(0, 0x01_02_03_04, false);
  assert.strictEqual(
    toBinary(buffer4Bytes),
    "00000001 00000010 00000011 00000100",
  );
  assert.strictEqual(toHex(buffer4Bytes), "01 02 03 04");

  assert.deepEqual(hexToArrayBuffer("01 02 03 04"), buffer4Bytes);
  assert.deepEqual(
    binaryToArrayBuffer("00000001 00000010 00000011 00000100"),
    buffer4Bytes,
  );
});

test("toBinary and toHex - no spaces", async () => {
  const buffer4Bytes = new ArrayBuffer(4);
  new DataView(buffer4Bytes).setUint32(0, 0x01_02_03_04);
  assert.strictEqual(
    toBinary(buffer4Bytes, false),
    "00000001000000100000001100000100",
  );
  assert.strictEqual(toHex(buffer4Bytes, false), "01020304");

  assert.deepEqual(hexToArrayBuffer("01020304"), buffer4Bytes);
  assert.deepEqual(
    binaryToArrayBuffer("00000001000000100000001100000100"),
    buffer4Bytes,
  );
});

test("toBinary - works without multiples of 8", async () => {
  assert.deepEqual(
    binaryToArrayBuffer("101"),
    new Uint8Array([0b0000_0101]).buffer,
  );
  assert.deepEqual(
    binaryToArrayBuffer("1111 0000"),
    new Uint8Array([0b1111_0000]).buffer,
  );
  // Show spaces are ignored.
  assert.deepEqual(
    binaryToArrayBuffer("11 1 1 000 0"),
    new Uint8Array([0b1111_0000]).buffer,
  );
});
