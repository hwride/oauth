import test from "node:test";
import assert from "node:assert/strict";
import {
  getBufferAsBinaryStr,
  getPlatformEndianness,
} from "../utils/binary.ts";

/*
JavaScript has no standalone byte primitive. Individual byte values are commonly represented as numbers from 0 to 255.
Byte sequences can be represented by the standard Uint8Array; Node.js also provides the Node-only Buffer type, which extends Uint8Array.

JavaScript number values are IEEE-754 floating-point values. JavaScript also has bigint, which represents arbitrary-precision integers.

Bitwise operators ultimately operate either on 32-bit number values or on bigint values.
Number and BigInt operands cannot be mixed, and unsigned right shift (>>>) only works with numbers.

When bitwise operators are applied to number operands, JavaScript converts each operand to a 32-bit integer first.
For non-negative values, values smaller than 32 bits are conceptually zero-padded on the left.
Values larger than 32 bits are reduced to their lowest 32 bits. Negative values use two’s-complement representation.

Most bitwise results are interpreted as signed 32-bit integers; >>> produces an unsigned 32-bit result.
 */

test("hex and binary notation", () => {
  /*
    Normal JavaScript numbers allow you to specify a number in base 10, e.g. 255
    Hex notation allows you to specify a number in base 16, eg 0xff
    Binary notation allows you to specify a number in base 2, eg 0b11111111

    But be aware: specifying 0xff or 0b11111111 is not specifying generic bits which could be interpreted differently
    depending on whether they are signed, unsigned, etc. It's literally just defining a number in a different base.

    That being said, you can pass number values into UInt8Array for example, and they will be converted to effectively
    that binary representation. See tests below for more details here.
   */

  // One hex letter is 4 bits
  assert.equal(0x0, 0);
  assert.equal(0x0, 0b00000000);

  assert.equal(0x4, 4);
  assert.equal(0x4, 0b00000100);

  assert.equal(0x9, 9);
  assert.equal(0x9, 0b00001001);

  // After 9 we go to a
  assert.equal(0xa, 10);
  assert.equal(0xa, 0b00001010);

  // Final letter is f
  assert.equal(0xf, 15);
  assert.equal(0xf, 0b00001111);

  // At which point we increase the next digit by 1
  assert.equal(0x10, 16);
  assert.equal(0x10, 0b00010000);

  assert.equal(0x11, 17);
  assert.equal(0x11, 0b00010001);

  // All the way up until ff
  assert.equal(0xff, 255);
  assert.equal(0xff, 0b11111111);

  // You can go above 1 byte with hex or binary notation
  assert.equal(0x100, 256);
  assert.equal(0x100, 0b100000000);

  // Here you can see negative numbers, more evidence these are no generic bit patterns but just numbers in a different base.
  assert.equal(-0x100, -256);
  assert.equal(-0x100, -0b100000000);
});

test("typed arrays", () => {
  /*
    An ArrayBuffer is a way to interact with raw memory.

    A TypedArray is a view on an underlying binary data buffer like an ArrayBuffer. You can have multiple different
    views on the same buffer and they will show different things.
   */
  // Create underlying binary data buffer of 1 byte.
  const memory = new ArrayBuffer(1);

  const uIntArr = new Uint8Array(memory); // Read the buffer as unsigned ints.
  const intArr = new Int8Array(memory); // Read the buffer as signed ints.

  // Set the number 255 as an unsigned int, in binary this is 1111 1111
  uIntArr.set([255]);

  assert.equal(uIntArr[0], 255); // See the unsigned int value = 255
  assert.equal(intArr[0], -1); // But the same bytes signed = -1

  // As mentioned in the hex and binary notation test above, 0x and 0b are just ways to define numbers in base 16 and
  // base 2, they are not a way to generically define bits. You can see this here:
  // This does match, because the number is unsigned.
  assert.equal(uIntArr[0], 0b11111111);
  // This does not match, why?
  // Because 0b11111111 is a base 2 number, which in base 10 = 255. A signed int with the bit pattern 11111111 = -1, not 255.
  // So this is proof hex and binary notation is just numbers in a different base, not describing a generic bit pattern
  // (even though it looks like one).
  assert.notEqual(intArr[0], 0b11111111);

  // But, the bit pattern of an unsigned int is equal to that same value in base 2,
  // i.e. the base 2 number 11111111 is represented as unsigned int by the bits 11111111.
  // This means we can trust that hex or binary notation passed to an unsigned int will correctly reflect that bit
  // pattern in the actual binary. E.g.:
  assert.equal(new Uint8Array([0b11111111])[0], 0b11111111);
  assert.equal(new Uint8Array([0b10101010])[0], 0b10101010);
  assert.equal(new Uint8Array([0xff])[0], 0b11111111);
  assert.equal(new Uint16Array([0xffff])[0], 0b1111111111111111);
  assert.equal(new Uint32Array([0xffffffff])[0], 0xffffffff);

  // This also means that we can accurately render the binary representation of an ArrayBuffer by creating a Uint8Array
  // view over it, looping over the output, and printing each value in base 2.
  assert.equal(getBufferAsBinaryStr(new Uint8Array([255]).buffer), "11111111");
  assert.equal(getBufferAsBinaryStr(new Uint8Array([0xff]).buffer), "11111111");
  assert.equal(getBufferAsBinaryStr(new Int8Array([-1]).buffer), "11111111");
  assert.equal(getBufferAsBinaryStr(new Uint8Array([5]).buffer), "00000101");
  assert.equal(
    getBufferAsBinaryStr(new Uint8Array([255, 0]).buffer),
    "11111111 00000000",
  );
  assert.equal(
    getBufferAsBinaryStr(new Uint16Array([0xffff]).buffer),
    "11111111 11111111",
  );
  // Note can't reliably do the below because depending on platform endianness, it could be 11111111 00000000 or 00000000 er11111111
  // assert.equal(getBufferAsBinary(new Uint16Array([0xff00]).buffer), "11111111 00000000");
});

test("endian-ness", () => {
  /*
    For 99% of software you can assume that the bits in your bytes will always have the least significant bit as the right-most byte.

    But if you have a single value that is composed of multiple bytes, such as a 16 bit/2 byte integer, it is not always the case
    that the high order byte will be first. If the most significant byte is first in memory it is big endian, otherwise little endian.
    Big endian is the way we naturally write and ready binary as humans. It is also what network protocols tend to use.

    For example 65280:
    - 11111111 00000000 = big endian
    - 00000000 11111111 = little endian
   */
  assert.equal(getPlatformEndianness(), "little-endian");
});

// AND bit operator
test("& operator", () => {
  // & with 0s always goes to 0
  assertBinaryByte(0b10101010 & 0b00000000, 0b00000000);
  // & with 1 goes to 1 if both sides are 1
  assertBinaryByte(0b10101010 & 0b11111111, 0b10101010);
});

// OR bit operator
test("| operator", () => {
  // | with 0s goes to 0 if both sides are 0
  assertBinaryByte(0b10101010 | 0b00000000, 0b10101010);
  // | with 1 always goes to 1
  assertBinaryByte(0b10101010 | 0b11111111, 0b11111111);
});

// NOT bit operator
test("~ operator", () => {
  // Note to demonstrate on a single byte need to mask off the other bits, because
  // the ~ operator works on 32 bits not 8 bits.
  assertBinaryByte(~0b00000000 & 0xff, 0b11111111);
  assertBinaryByte(~0b11111111 & 0xff, 0b00000000);
});

/**
 * Assert two byte values, displaying them in binary form on failure.
 *
 * JavaScript has no standalone byte primitive. Uint8Array is a built-in typed array
 * that stores one unsigned 8-bit value per element, but exposes indexed values as
 * JavaScript numbers from 0–255.
 */
function assertBinaryByte(actual: number, expected: number) {
  assert.ok(Number.isInteger(actual) && actual >= 0 && actual <= 0xff);
  assert.ok(Number.isInteger(expected) && expected >= 0 && expected <= 0xff);

  assert.strictEqual(
    actual.toString(2).padStart(8, "0"),
    expected.toString(2).padStart(8, "0"),
  );
}
