import test from "node:test";
import assert from "node:assert/strict";
import { type HashAlgorithm } from "./hmac-one-time-password.ts";
import { hexToArrayBuffer } from "../util/binary.ts";
import {
  calculateTimeStepNumber,
  createTimeBasedOneTimePasswordValidator,
  timeBasedOneTimePasswordCode,
  type TotpOptionsValidator,
} from "./time-based-one-time-password.ts";

/** Uses the same secret as the HMAC spec/tests. */
const testSecret = hexToArrayBuffer("3132333435363738393031323334353637383930");
/** Constant value for use in tests for consistent code checks. */
const testTimeh12m00s00 = new Date("2026-10-27T12:00:00.000Z");
const testTimeh12m30s00 = new Date("2026-10-27T12:00:30.000Z");

/**
 * Known codes for the test secret and default code config. You can check the in the numeric test.
 */
const knownCodes = Object.freeze({
  h11m59s00: "480534",
  h11m59s30: "586766",
  h12m00s00: "472600",
  h12m00s30: "480583",
});

test("timeBasedOneTimePassword -  basic check", async () => {
  const totpValidator = createTimeBasedOneTimePasswordValidator({
    key: testSecret,
    hashAlgorithm: "SHA1",
  });
  const time = testTimeh12m00s00;
  const code1Result = await totpValidator.validate("472600", {
    time: testTimeh12m00s00,
  });
  assert.strictEqual(code1Result.isValid, true);

  // Prove it doesn't work with the next code.
  const code2Result = await totpValidator.validate("480583", {
    time,
  });
  assert.strictEqual(code2Result.isValid, false);
});

test("timeBasedOneTimePassword - validate works without options", async () => {
  const totpValidator = createTimeBasedOneTimePasswordValidator({
    key: testSecret,
  });
  const code1Result = await totpValidator.validate("472600");
  assert.strictEqual(typeof code1Result.isValid, "boolean");
});

test("timeBasedOneTimePassword - validation", async () => {
  const expectError = (
    options: Partial<TotpOptionsValidator>,
    errorMsg: string,
  ) => {
    try {
      createTimeBasedOneTimePasswordValidator({
        key: testSecret,
        ...options,
      });
    } catch (e) {
      assert.equal(e.message, errorMsg);
      return;
    }
    assert.equal(true, false);
  };

  // timeStepSeconds
  expectError(
    { timeStepSeconds: Infinity },
    "Invalid value for timeStepSeconds, must be > 0",
  );
  expectError(
    { timeStepSeconds: 0 },
    "Invalid value for timeStepSeconds, must be > 0",
  );
  expectError(
    { timeStepSeconds: -1 },
    "Invalid value for timeStepSeconds, must be > 0",
  );

  // allowedTimeSteps
  expectError(
    { allowedTimeSteps: Infinity },
    "Invalid value for allowedTimeSteps, must be > 0",
  );
  expectError(
    { allowedTimeSteps: 0 },
    "Invalid value for allowedTimeSteps, must be > 0",
  );
  expectError(
    { allowedTimeSteps: -1 },
    "Invalid value for allowedTimeSteps, must be > 0",
  );

  // hashAlgorithm
  expectError(
    { hashAlgorithm: "SHA-3" as HashAlgorithm },
    "Unsupported hash algorithm. Supported: SHA1,SHA256,SHA512",
  );
});

const totpSpecTestSecrets = Object.freeze({
  sha1: new TextEncoder().encode("12345678901234567890").buffer,
  sha256: new TextEncoder().encode("12345678901234567890123456789012").buffer,
  sha512: new TextEncoder().encode(
    "1234567890123456789012345678901234567890123456789012345678901234",
  ).buffer,
});

const totpSpecTestValues = [
  {
    unixTime: 59,
    timeStepNumber: 0x0000000000000001n,
    sha1: "94287082",
    sha256: "46119246",
    sha512: "90693936",
  },
  {
    unixTime: 1_111_111_109,
    timeStepNumber: 0x00000000023523ecn,
    sha1: "07081804",
    sha256: "68084774",
    sha512: "25091201",
  },
  {
    unixTime: 1_111_111_111,
    timeStepNumber: 0x00000000023523edn,
    sha1: "14050471",
    sha256: "67062674",
    sha512: "99943326",
  },
  {
    unixTime: 1_234_567_890,
    timeStepNumber: 0x000000000273ef07n,
    sha1: "89005924",
    sha256: "91819424",
    sha512: "93441116",
  },
  {
    unixTime: 2_000_000_000,
    timeStepNumber: 0x0000000003f940aan,
    sha1: "69279037",
    sha256: "90698825",
    sha512: "38618901",
  },
  {
    unixTime: 20_000_000_000,
    timeStepNumber: 0x0000000027bc86aan,
    sha1: "65353130",
    sha256: "77737706",
    sha512: "47863826",
  },
] as const;

test("TOTP (RFC 6238) spec tests - SHA-1", async () => {
  for (const testValue of totpSpecTestValues) {
    assert.equal(
      BigInt(calculateTimeStepNumber(testValue.unixTime, 30)),
      testValue.timeStepNumber,
    );

    const { code } = await timeBasedOneTimePasswordCode({
      key: totpSpecTestSecrets.sha1,
      time: new Date(testValue.unixTime * 1000),
      codeLength: 8,
      hashAlgorithm: "SHA1",
    });
    assert.equal(code, testValue.sha1);
  }
});

test("TOTP (RFC 6238) spec tests - SHA-256", async () => {
  for (const testValue of totpSpecTestValues) {
    assert.equal(
      BigInt(calculateTimeStepNumber(testValue.unixTime, 30)),
      testValue.timeStepNumber,
    );

    const { code } = await timeBasedOneTimePasswordCode({
      key: totpSpecTestSecrets.sha256,
      time: new Date(testValue.unixTime * 1000),
      codeLength: 8,
      hashAlgorithm: "SHA256",
    });
    assert.equal(code, testValue.sha256);
  }
});

test("TOTP (RFC 6238) spec tests - SHA-512", async () => {
  for (const testValue of totpSpecTestValues) {
    assert.equal(
      BigInt(calculateTimeStepNumber(testValue.unixTime, 30)),
      testValue.timeStepNumber,
    );

    const { code } = await timeBasedOneTimePasswordCode({
      key: totpSpecTestSecrets.sha512,
      time: new Date(testValue.unixTime * 1000),
      codeLength: 8,
      hashAlgorithm: "SHA512",
    });
    assert.equal(code, testValue.sha512);
  }
});

test("TOTP defaults to SHA-1", async () => {
  const testValue = totpSpecTestValues[0];
  const { code } = await timeBasedOneTimePasswordCode({
    key: totpSpecTestSecrets.sha1,
    time: new Date(testValue.unixTime * 1000),
    codeLength: 8,
  });

  assert.equal(code, testValue.sha1);
});

test("timeBasedOneTimePassword - 2 allowed time steps", async () => {
  const totpValidator = createTimeBasedOneTimePasswordValidator({
    key: testSecret,
    allowedTimeSteps: 2,
    hashAlgorithm: "SHA1",
  });
  const time = testTimeh12m00s00;

  assert.strictEqual(
    (await totpValidator.validate(knownCodes.h12m00s00, { time })).isValid,
    true,
    "Code for 12:00:00 - should work",
  );

  assert.strictEqual(
    (await totpValidator.validate(knownCodes.h11m59s30, { time })).isValid,
    true,
    "Code for 11:59:30 - should work as it's 1 time step behind",
  );

  assert.strictEqual(
    (await totpValidator.validate(knownCodes.h11m59s00, { time })).isValid,
    false,
    "Code for 11:59:00 - should not work as it's 2 time steps behind",
  );

  assert.strictEqual(
    (await totpValidator.validate(knownCodes.h12m00s30, { time })).isValid,
    false,
    "Code for 12:00:30 - should not work as it's 1 time step ahead",
  );
});

test("timeBasedOneTimePassword - cannot re-use code", async () => {
  const totpValidator = createTimeBasedOneTimePasswordValidator({
    key: testSecret,
    hashAlgorithm: "SHA1",
  });
  const time = testTimeh12m00s00;
  const code1Result = await totpValidator.validate("472600", {
    time: testTimeh12m00s00,
  });
  assert.strictEqual(code1Result.isValid, true);

  // Prove it doesn't work with the next code.
  const codeReuseResult = await totpValidator.validate("472600", {
    time,
  });
  assert.strictEqual(codeReuseResult.isValid, false);
});

test("timeBasedOneTimePassword - in-memory code store - cannot re-use the newest code after cache eviction", async () => {
  const totpValidator = createTimeBasedOneTimePasswordValidator({
    key: testSecret,
    hashAlgorithm: "SHA1",
  });

  // This code will now be stored in the code store so cannot be re-used.
  assert.strictEqual(
    (
      await totpValidator.validate(knownCodes.h12m00s00, {
        time: testTimeh12m00s00,
      })
    ).isValid,
    true,
  );
  // Check T+30s with the next code, should work and overwrite the cache value.
  assert.strictEqual(
    (
      await totpValidator.validate(knownCodes.h12m00s30, {
        time: testTimeh12m30s00,
      })
    ).isValid,
    true,
  );
  // Check T+30s again - makes sure that h12m00s30 code value was stored in the cache and we didn't clear the newer
  // one by accident.
  assert.strictEqual(
    (
      await totpValidator.validate(knownCodes.h12m00s30, {
        time: testTimeh12m30s00,
      })
    ).isValid,
    false,
  );
});

test("timeBasedOneTimePassword - cannot re-use code - but two steps generate the same code", async () => {
  // Look first, here's proof we can generate the same code across two time steps.
  const time = new Date("1970-11-13T05:29:00.000Z");
  const timePrevStep = new Date("1970-11-13T05:28:30.000Z");
  const first = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time,
    hashAlgorithm: "SHA1",
  });
  const second = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: timePrevStep,
    hashAlgorithm: "SHA1",
  });
  assert.equal(first.code, "911617");
  assert.equal(second.code, "911617");

  // Now we assert that we allow each code once. Because it could be the case you enter once code, the time step ticks
  // over, then if we simply blocked the same code being used twice they could not enter the second code.
  const totpValidator = createTimeBasedOneTimePasswordValidator({
    key: testSecret,
    allowedTimeSteps: 2,
    hashAlgorithm: "SHA1",
  });
  // Check the code works the first time, this claims 05:28:30 code
  assert.strictEqual(
    (await totpValidator.validate("911617", { time })).isValid,
    true,
  );
  // Check the code works again, this claims 05:29:00 code
  assert.strictEqual(
    (await totpValidator.validate("911617", { time })).isValid,
    true,
  );
  // Check the code does not work a 3rd time, as both time step versions of the code have been claimed.
  assert.strictEqual(
    (await totpValidator.validate("911617", { time })).isValid,
    false,
  );
});

test("timeBasedOneTimePasswordCode - numeric", async () => {
  // 11:59:00
  const { code: code1 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date("2026-10-27T11:59:00.000Z"),
    hashAlgorithm: "SHA1",
  });
  assert.strictEqual(code1, knownCodes.h11m59s00);

  // 11:59:30
  const { code: code2 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date("2026-10-27T11:59:30.000Z"),
    hashAlgorithm: "SHA1",
  });
  assert.strictEqual(code2, knownCodes.h11m59s30);

  // 12:00:00
  const { code: code3 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: testTimeh12m00s00,
    hashAlgorithm: "SHA1",
  });
  assert.strictEqual(code3, knownCodes.h12m00s00);

  // 12:30:00
  const { code: code4 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date("2026-10-27T12:00:30.000Z"),
    hashAlgorithm: "SHA1",
  });
  assert.strictEqual(code4, knownCodes.h12m00s30);
});

test("timeBasedOneTimePasswordCode - alphanumeric", async () => {
  const { code } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    codeType: "alphanumeric",
    hashAlgorithm: "SHA1",
    time: testTimeh12m00s00,
  });
  assert.strictEqual(code, "2MSUBE");
});

test("timeBasedOneTimePasswordCode - defaults to current time if not provided", async () => {
  const { code } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    hashAlgorithm: "SHA1",
  });
  assert.strictEqual(typeof code, "string");
  assert.strictEqual(code.length, 6);
});

// Spec: The implementation of this algorithm MUST support a time value T
// larger than a 32-bit integer when it is beyond the year 2038.
test("timeBasedOneTimePasswordCode - time beyond 2038", async () => {
  const { code } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    hashAlgorithm: "SHA1",
    time: new Date("2040-10-27T12:00:00.000Z"),
  });
  assert.strictEqual(code, "713614");
});

test("timeBasedOneTimePasswordCode - two codes within the same time step are the same", async () => {
  const { code: code0 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date(0),
  });
  const { code: code29 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date(29 * 1000), // 29 seconds
  });
  const { code: code30 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date(30 * 1000), // 30 seconds
  });
  assert.strictEqual(code0, code29); // Same time step so should be equal
  assert.notStrictEqual(code29, code30); // Next time step so should not match
});

test("timeBasedOneTimePasswordCode - can set custom time step", async () => {
  const { code: code0 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date(0),
    timeStepSeconds: 60,
  });
  const { code: code29 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date(29 * 1000), // 29 seconds
    timeStepSeconds: 60,
  });
  const { code: code30 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date(30 * 1000), // 30 seconds
    timeStepSeconds: 60,
  });
  const { code: code61 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date(60 * 1000), // 61 seconds
    timeStepSeconds: 60,
  });
  assert.strictEqual(code0, code29); // Same time step so should be equal
  assert.strictEqual(code0, code30); // Same time step so should be equal
  assert.notStrictEqual(code0, code61); // Next time step so should not match
});

test("timeBasedOneTimePasswordCode - validation", async () => {
  const expectError = async (
    options: Partial<TotpOptionsValidator>,
    errorMsg: string,
  ) => {
    try {
      await timeBasedOneTimePasswordCode({
        key: testSecret,
        ...options,
      });
    } catch (e) {
      assert.equal(e.message, errorMsg);
      return;
    }
    assert.equal(true, false);
  };

  // timeStepSeconds
  await expectError(
    { timeStepSeconds: Infinity },
    "Invalid value for timeStepSeconds, must be > 0",
  );
  await expectError(
    { timeStepSeconds: 0 },
    "Invalid value for timeStepSeconds, must be > 0",
  );
  await expectError(
    { timeStepSeconds: -1 },
    "Invalid value for timeStepSeconds, must be > 0",
  );

  // hashAlgorithm
  await expectError(
    { hashAlgorithm: "SHA-3" as HashAlgorithm },
    "Unsupported hash algorithm. Supported: SHA1,SHA256,SHA512",
  );
});

test("calculateTimeStepNumber", () => {
  assert.strictEqual(calculateTimeStepNumber(0, 30), 0);
  assert.strictEqual(calculateTimeStepNumber(29, 30), 0);
  assert.strictEqual(calculateTimeStepNumber(30, 30), 1);
  assert.strictEqual(calculateTimeStepNumber(59, 30), 1);
  assert.strictEqual(calculateTimeStepNumber(60, 30), 2);
});
