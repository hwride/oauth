import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { getBufferAsBinaryStr, getPlatformEndianness } from "./binary.ts";

/*
  The file contains some tests around JavaScript binary handling and operators.
 */

/*
  ## Interacting with raw memory ##
  - In JavaScript ArrayBuffers are a way to assign raw memory, but not read or write it.
  - TypedArrays allow you to read and write memory in ArrayBuffers in different formats. E.g. as signed or unsigned ints
    of 8, 16, 32, or 64 bit length, with classes such as Uint8Array or In32Array.
  - Different TypedArrays can view the same piece of memory.
  - The Uint8Array class is the easiest way to represent a sequence of bytes, as it does not care about endian-ness.
  - The larger typed array classes such as Uint16Array represent two bytes in each array entry, but then you must care
    about endian-ness. They will simplify read and write with this computer's default endian, so if you require a
    specific endian this may not behave as you expect.
  - The DataView class can be used to specifically read and write with a certain endian-ness.

  ## Binary notation and bitwise operators ##
  - JavaScript has no standalone byte primitives. Instead, byte values are represented as the JavaScript number primitive
    for e.g. 255 = the byte 11111111, or the JavaScript bigint primitive for e.g. 255n.
  - JavaScript lets you write numbers in base 2 with 0b11111111, base 8 with 0o377, or base 16 with 0xff. Suffix with
    an n for bigint, e.g. 0b11111111n, 0o377n, 0xffn.
  - JavaScript number values are IEEE-754 floating-point values. JavaScript bigint values are arbitrary-precision integers.
  - Because 0b11111111 and 0xff are JavaScript numbers not raw byte sequences you must be careful when using them and
    not assume you are describing raw bytes.
  - Bitwise operators on numbers convert operators and results to 32-bit signed integers. This is makes the fact raw
    binary notation such as 0b11111111 particularly visible as it means for e.g. 0xffffffff & 0xf0f0f0f0 !== 0xffffffff
    in raw JavaScript. See "bitwise operators convert to signed 32 bits" below for more info.
  - >>> is an exception to this and converts results in an un-signed 32-bit integer.
  - If bitwise operators are used on bigints they use arbitrary precision integers.
    e.g. 0xffffffffn & 0xffff0000n = 0xffff0000n
  - Number and BigInt operands cannot be mixed, and unsigned right shift (>>>) only works with numbers.

  ## Two's complement ##
  This is a method for working out the binary of a negative signed number. Ths method:
  1) Get the binary for the positive number, for your int value, e.g. for signed 8-bit integer - 3 = 0000 0011
  2) Flip the bits = 1111 1100
  3) Add 1 = 1111 1101

  Or to work out what number a negative signed 8-bit int is:
  1) Get the binary, e.g. 1111 1101
  2) Remove 1 = 1111 1100
  3) Flip the bits = 0000 0011 = 3, therefore -3

  Now 0b00000000n is all 0s.
  NOT of 0 is 1, so it becomes all 1s.
  Lets do our negative two's complement algorithm:
  1) Get the binary = 1111 1111....
  2) Remove 1 = 1111 1111 ... 1110
  3) Flip the bits = 0000 0000 .... 0001 = 1, therefore -1
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

describe("ArrayBuffer views and endianness", () => {
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
    assert.equal(
      getBufferAsBinaryStr(new Uint8Array([255]).buffer),
      "11111111",
    );
    assert.equal(
      getBufferAsBinaryStr(new Uint8Array([0xff]).buffer),
      "11111111",
    );
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

    For example 65280 (0xff00 in hex):
    - 11111111 00000000 = big endian (note binary notation matches this 0b11111111_00000000)
    - 00000000 11111111 = little endian

    You can examine the actual bytes in a piece of memory using the Uint8Array trick discussed in the previous test.
    You can use this to create a function which will tell you the endian-ness of the current platform.
   */
    // commented out because we don't know what the endian-ness of the platform will actually be.
    console.log("This platform is " + getPlatformEndianness());
  });

  test("DataView", () => {
    /*
    There is another tool the platform offers us to deal with endian-ness - DataView.
    This class allows you to write to ArrayBuffers with big or little endian specifically.
   */
    // Demo with sets
    const buffer = new ArrayBuffer(2);
    new DataView(buffer).setUint16(0, 0xff00, true /* littleEndian */);
    assert.equal(getBufferAsBinaryStr(buffer), "00000000 11111111");

    new DataView(buffer).setUint16(0, 0xff00, false /* bigEndian */);
    assert.equal(getBufferAsBinaryStr(buffer), "11111111 00000000");

    // Demo with gets
    new DataView(buffer).setUint16(0, 0xff00, false /* bigEndian */);
    assert.equal(new DataView(buffer).getUint16(0, false), 0xff00);
    assert.equal(new DataView(buffer).getUint16(0, true), 0x00ff);

    // You could use DataView to do an alternative implementation of platform endian-ness check:
    function getPlatformEndiannessDataView(): "big-endian" | "little-endian" {
      // Create a 16 bit unsigned int, this will be laid out according to the platform's endian-ness.
      const uInt16Bit = new Uint16Array([0xff00]);
      // Read that same 16 bit unsigned int as big endian, and check if the value matches.
      const valueBigEndian = new DataView(uInt16Bit.buffer).getUint16(0, false); // false = big-endian

      return valueBigEndian === 0xff00 ? "big-endian" : "little-endian";
    }
    console.log(
      "This platform is " + getPlatformEndiannessDataView() + " (via DataView)",
    );
  });

  test("Uint8ClampedArray clamps values instead of wrapping them", () => {
    /*
     * Uint8ClampedArray is useful for values such as RGBA pixel channels.
     * Brightness or colour calculations should stop at 0 and 255 instead of
     * wrapping around, as they would with Uint8Array.
     */
    // For values 255 >= x >= 0 these are the same.
    assert.strictEqual(new Uint8Array([0])[0], 0);
    assert.strictEqual(new Uint8ClampedArray([0])[0], 0);
    assert.strictEqual(new Uint8Array([255])[0], 255);
    assert.strictEqual(new Uint8ClampedArray([255])[0], 255);

    // Values outside this range are clamped for Uint8ClampedArray, but not regular Uint8Array.
    assert.strictEqual(new Uint8Array([256])[0], 0);
    assert.strictEqual(new Uint8ClampedArray([256])[0], 255);
    assert.strictEqual(new Uint8Array([-1])[0], 255);
    assert.strictEqual(new Uint8ClampedArray([-1])[0], 0);
  });
});

describe("bitwise operators", () => {
  /*
    Bitwise operators convert their operands and result to signed 32-bit numbers, except >>>
    which converts to un-signed.

    If the numbers are smaller they will be essentially left padded.
    If they are bigger they will have their most significant bits dropped until 32 bits are left.
   */
  test("bitwise operators used with numbers convert to signed 32 bits integers", () => {
    // If a value is passed in that's bigger than 32 bits, the most significant bites are dropped until it's 32-bits.
    assert.notEqual(0xffff_0000_0000 & 0xffff_0000_0000, 0xffff_0000_0000);
    assert.equal(0xffff_0000_0000 & 0xffff_0000_0000, 0x0000_0000);

    // 32 bits
    // this & seems to work as expected because it just produces 0
    assert.strictEqual(0xf0f0f0f0 & 0x00000000, 0x00000000);
    // but here not: because the most significant bit is 1
    // 0xf0f0f0f0 in base 16    = 4042322160
    // 0xf0f0f0f0 as signed int = -252645136 (MSB of 1 means the number is negative)
    assert.notEqual(0xf0f0f0f0 & 0xffffffff, 0xf0f0f0f0);
    assert.equal(0xf0f0f0f0 & 0xffffffff, -252645136);

    // This is another demo about why you can't try and write plain binary or hex notation and
    // expect it to actually match the underlying bits. Multiple JS factors get in the way:
    // 1. Binary notation are base 2 or 16 numbers, not describing underlying bit patterns.
    // 2. Bitwise operators convert operands and result to be signed 32-bit numbers.

    // 8 bits
    // As above this appears to work because it just produces 0.
    assert.equal(0b10101010 & 0b00000000, 0b00000000);
    // Unlike the 32 bit example above this appears to work, why?
    // Because the result is converted to 32-bit signed and left padded with 0s.
    // Left padded with 0s means it's a positive number, and also mean all the 8 digits we used in our
    // bitwise operation are left intact. So it all appears to work, but only by luck. The 32-bit
    // example above better demonstrates the issues.
    assert.equal(0b10101010 & 0b11111111, 0b10101010);

    // So if we want to do bitwise operators on hex or binary notation, and be able to check the
    // result, how could we do it? We can make use of the unsigned integer typed array classes.
    // 32-bit
    // Why does this work? Unsigned integer typed array classes will preserve the bit pattern produced by the number
    // output from the bitwise operation, and then read it according to its own type.
    // For Uint32Array that means essentially outputting the uint32 value for the bits of the given number.
    assert.notEqual(0xf0f0f0f0 & 0xffffffff, 0xf0f0f0f0);
    assert.equal(new Uint32Array([0xf0f0f0f0 & 0xffffffff])[0], 0xf0f0f0f0);
    assert.equal(new Uint8Array([0b10101010 & 0b11111111])[0], 0b10101010);
    // Or you could do the opposite and make expected signed 32-bit integer to match what bitwise operators produce
    assert.equal(0xf0f0f0f0 & 0xffffffff, new Int32Array([0xf0f0f0f0])[0]);

    // See here it doesn't work for signed integer classes as the first bit can make the number negative.
    assert.notEqual(new Int8Array([0b10101010 & 0b11111111])[0], 0b10101010);
    // That could be fixed by using the class the other side too.
    // But there's no point, if we're just trying to do accurate bitwise operations using binary or hex notation
    // simply use the unsigned variants as they will always match the plain binary or hex notation values.
    assert.equal(
      new Int8Array([0b10101010 & 0b11111111])[0],
      new Int8Array([0b10101010])[0],
    );

    // >>> X = unsigned right shift
    // this operator does 2 things:
    // 1. converts the number to be un-signed for the same bits it has now
    // 2. shifts the bits right by X, left padding with 0
    // you can also achieve our goal using >>> 0 which means skip step 2 entirely so
    // it basically just becomes make this number unsigned. e.g.:
    assert.notEqual(0xf0f0f0f0 & 0xffffffff, 0xf0f0f0f0);
    assert.equal((0xf0f0f0f0 & 0xffffffff) >>> 0, 0xf0f0f0f0);
    assert.equal((0b10101010 & 0b11111111) >>> 0, 0b10101010);
  });

  test("bitwise operators used with bigints use signed arbitrary precision integers", () => {
    // Here's an e.g. that regular numbers get cut down to 32-bits
    assert.notEqual(0xffff_0000_0000 & 0xffff_0000_0000, 0xffff_0000_0000);
    assert.equal(0xffff_0000_0000 & 0xffff_0000_0000, 0x0000_0000);

    // And here shows this isn't a problem for bigints.
    assert.equal(0xffff_0000_0000n & 0xffff_0000_0000n, 0xffff_0000_0000n);

    /*
      So the issue we have when using numbers were used in bitwise operations was they were converted to
      32-bit signed integers, which can make for confusing looking results due to a 1 at the start making a number
      negative with a different value.

      But bigints do not get forced to 32-bit. This means they avoid the confusing looking case around some of the
      bitwise operations appearing not work as expected, because their most significant bit dosn't get forced to 0
      they have infinite extra bits at the start.
     */
    // 32 bits
    assert.equal(0xf0f0_f0f0n & 0x0000_0000n, 0x0000_0000n);
    assert.equal(0xf0f0_f0f0n & 0xffff_ffffn, 0xf0f0_f0f0n);
    assert.notEqual(0xf0f0_f0f0 & 0xffff_ffff, 0xf0f0_f0f0); // See how it didn't work for numbers instead of bigints

    // 8 bits
    assert.equal(0b1010_1010n & 0b0000_0000n, 0b0000_0000n);
    assert.equal(0b1010_1010n & 0b1111_1111n, 0b1010_1010n);

    // Note that while using bigint does make most of the bitwise operations appear to work correctly using binary or hex
    // notation for the operation and result, it's not a full solution.
    // See this NOT example, which is correct conceptually, but fails here:
    assert.notEqual(~0b00000000n, 0b11111111n);
    assert.equal(~0b00000000n, -1n);
    /*
     To understand this first we need to understand two's complement, see the top of the page for an explanation.

     Now 0b00000000n is all 0s.
     NOT of 0 is 1, so it becomes all 1s.
     Lets do our negative two's complement algorithm:
     1) Get the binary = 1111 1111....
     2) Remove 1 = 1111 1111 ... 1110
     3) Flip the bits = 0000 0000 .... 0001 = 1, therefore -1
     */

    // Another example
    assert.notEqual(~0b11110000n, 0b00001111n);
    assert.equal(~0b11110000n, -241n);
  });

  // The byte-focused operator tests below use assertByteEqual, beware regular comparison has edge cases. See comment
  // for details.
  test("& operator - AND", () => {
    // & with 1s goes to 1 if both sides are 1
    assertByteEqual(0b10101010 & 0b11111111, 0b10101010);
    // & with 0 always goes to 0
    assertByteEqual(0b10101010 & 0b00000000, 0b00000000);
  });

  test("&= operator - AND assignment", () => {
    // Combines and & with an assignment
    let num = 0b10101010;
    num &= 0b11111111;
    assertByteEqual(num, 0b10101010);

    // Demo here assignment also returns the result.
    assertByteEqual((num &= 0b00000000), 0b00000000);
    assertByteEqual(num, 0b00000000);
  });

  test("| operator - OR", () => {
    // | with 0s goes to 0 if both sides are 0
    assertByteEqual(0b10101010 | 0b00000000, 0b10101010);
    // | with 1 always goes to 1
    assertByteEqual(0b10101010 | 0b11111111, 0b11111111);
  });

  test("|= operator - OR assignment", () => {
    // Combines | with an assignment
    let num = 0b10101010;
    num |= 0b00000000;
    assertByteEqual(num, 0b10101010);

    // Assignment also returns the result.
    assertByteEqual((num |= 0b11111111), 0b11111111);
    assertByteEqual(num, 0b11111111);
  });

  test("^ operator - XOR", () => {
    // Gives a 1 if one but not both bits are 1
    assertByteEqual(0b00000110 ^ 0b00000101, 0b00000011);
  });
  test("^= operator - XOR assignment", () => {
    // Combines ^ with an assignment
    let num = 0b10101010;
    num ^= 0b00000000;
    assertByteEqual(num, 0b10101010);

    // Assignment also returns the result.
    assertByteEqual((num ^= 0b11111111), 0b01010101);
    assertByteEqual(num, 0b01010101);
  });

  test("~ operator - NOT", () => {
    // NOT flips all bits
    // Not using bigint here as it suffers from the problem described in
    // "bitwise operators used with bigints use signed arbitrary precision integers"
    assertByteEqual(~0b00000000, 0b11111111);
    assertByteEqual(~0b11110000, 0b00001111);
  });

  test("<< operator - bitwise shift left", () => {
    // shits bits left by the give amount, filling remaining bits with 0
    assertByteEqual(0b11111111 << 1, 0b11111110);
    assertByteEqual(0b11111111 << 2, 0b11111100);
    assertByteEqual(0b11111111 << 4, 0b11110000);
    assertByteEqual(0b11111111 << 8, 0b00000000);
    assertByteEqual(0b11111111 << 9, 0b00000000);
  });

  test(">> operator - bitwise shift right", () => {
    // shits bits right by the give amount, filling remaining bits with 0
    assertByteEqual(0b11111111 >> 1, 0b01111111);
    assertByteEqual(0b11111111 >> 2, 0b00111111);
    assertByteEqual(0b11111111 >> 4, 0b00001111);
    assertByteEqual(0b11111111 >> 8, 0b00000000);
    assertByteEqual(0b11111111 >> 9, 0b00000000);
  });

  test(">>> operator - bitwise shift right, unsigned", () => {
    // same as bit shift right, but products an unsigned result
    // here's a demo the same assertions as the bitwise shift right test pass
    assertByteEqual(0b11111111 >>> 1, 0b01111111);
    assertByteEqual(0b11111111 >>> 2, 0b00111111);
    assertByteEqual(0b11111111 >>> 4, 0b00001111);
    assertByteEqual(0b11111111 >>> 8, 0b00000000);
    assertByteEqual(0b11111111 >>> 9, 0b00000000);

    // now here's some demos we don't need our util because it converts the result to unsigned, matching the raw binary notation
    // note have to demo with 32-bits, using 0b11111111 >> 0 is 8-bit so the MSB would already be 0 due to the padding to 32-bits,
    // meaning the conversion to signed wouldn't cause the number to flip from negative to positive.
    // But using 0xffffffff is already 32-bit so the MSB stays at 1 which is negative, so we get to prove >>> keeps it
    // unsigned and doesn't flip it to negative.
    assert.equal(0xffffffff >>> 0, 0xffffffff);
    // Here we see the regular >> operator converts to signed, which = -1
    assert.notEqual(0xffffffff >> 0, 0xffffffff);
    assert.equal(0xffffffff >> 0, -1);
  });

  /**
   * Helper function to do a comparison between numbers that represent bytes.
   *
   * Allows conceptually accurate binary operations using binary notation, e.g.:
   * assertByteEqual(0b1111_0000 | 0b0000_0000, 0b1111_0000)
   *
   * Important note: this will only work correctly on values up to bytes. If you pass in other values you may not
   * get expected results. E.g. assertByteEqual(0x1234_5678, 0xdead_be78).
   *
   * Works around a couple of the JS issues here:
   * 1. Binary notation is actually converted to a JavaScript number
   * 2. Numbers when passed to bitwise operators are converted to 32-bit signed integers. This can cause issues with
   * negative numbers if the most significant bit is swapped to a 1.
   */
  function assertByteEqual(actual: number, expected: number) {
    const actualUnsigned = new Uint8Array([actual])[0];
    const expectedUnsigned = new Uint8Array([expected])[0];
    assert.equal(actualUnsigned, expectedUnsigned);
  }
});
