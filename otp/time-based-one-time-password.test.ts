import test from "node:test";
import assert from "node:assert/strict";
import {
  dynamicTruncation,
  hmacOneTimePassword,
} from "./hmac-one-time-password.ts";
import { hexToArrayBuffer, toHex } from "../util/binary.ts";
import {
  calculateTime,
  timeBasedOneTimePasswordCode,
  timeBasedOneTimePassword,
} from "./time-based-one-time-password.ts";

// Uses the same secret as the HMAC spec/tests.
const testSecret = hexToArrayBuffer("3132333435363738393031323334353637383930");

test("timeBasedOneTimePassword - defaults", async () => {
  const time = new Date("2026-10-27T12:00:00.000Z");
  const code1Result = await timeBasedOneTimePassword({
    key: testSecret,
    time: new Date("2026-10-27T12:00:00.000Z"),
    expectedCode: "472600",
  });
  assert.strictEqual(code1Result.isValid, true);
  assert.strictEqual(code1Result.matchingCode, "472600");

  // Prove it doesn't work with the next code.
  const code2Result = await timeBasedOneTimePassword({
    key: testSecret,
    time,
    allowedTimeSteps: 1,
    expectedCode: "480583",
  });
  assert.strictEqual(code2Result.isValid, false);
});

test("timeBasedOneTimePassword - 2 allowed time steps", async () => {
  const time = new Date("2026-10-27T12:00:00.000Z");
  const code1Result = await timeBasedOneTimePassword({
    key: testSecret,
    time,
    allowedTimeSteps: 2,
    expectedCode: "472600",
  });
  assert.strictEqual(code1Result.isValid, true);
  assert.strictEqual(code1Result.matchingCode, "472600");

  // See the same code for the next time step is also valid due to 2 allowed time steps.
  const code2Result = await timeBasedOneTimePassword({
    key: testSecret,
    time,
    allowedTimeSteps: 2,
    expectedCode: "480583",
  });
  assert.strictEqual(code2Result.isValid, true);
  assert.strictEqual(code2Result.matchingCode, "480583");

  // Proved it doesn't work when allowed time steps is 1.
  const code3Result = await timeBasedOneTimePassword({
    key: testSecret,
    time,
    allowedTimeSteps: 1,
    expectedCode: "480583",
  });
  assert.strictEqual(code3Result.isValid, false);
});

test("numeric", async () => {
  const { code } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date("2026-10-27T12:00:00.000Z"),
  });
  assert.strictEqual(code, "472600");
});

test("alphanumeric", async () => {
  const { code } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    codeType: "alphanumeric",
    time: new Date("2026-10-27T12:00:00.000Z"),
  });
  assert.strictEqual(code, "2MSUBE");
});

test("defaults to current time if not provided", async () => {
  const { code } = await timeBasedOneTimePasswordCode({
    key: testSecret,
  });
  assert.strictEqual(typeof code, "string");
  assert.strictEqual(code.length, 6);
});

// Spec: The implementation of this algorithm MUST support a time value T
// larger than a 32-bit integer when it is beyond the year 2038.
test("time beyond 2038", async () => {
  const { code } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date("2040-10-27T12:00:00.000Z"),
  });
  assert.strictEqual(code, "713614");
});

test("two codes within the same time step are the same", async () => {
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

test("can set custom time step", async () => {
  const { code: code0 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date(0),
    timeStep: 60,
  });
  const { code: code29 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date(29 * 1000), // 29 seconds
    timeStep: 60,
  });
  const { code: code30 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date(30 * 1000), // 30 seconds
    timeStep: 60,
  });
  const { code: code61 } = await timeBasedOneTimePasswordCode({
    key: testSecret,
    time: new Date(60 * 1000), // 61 seconds
    timeStep: 60,
  });
  assert.strictEqual(code0, code29); // Same time step so should be equal
  assert.strictEqual(code0, code30); // Same time step so should be equal
  assert.notStrictEqual(code0, code61); // Next time step so should not match
});

test("calculateTime", () => {
  assert.strictEqual(calculateTime(0, 30), 0);
  assert.strictEqual(calculateTime(29, 30), 0);
  assert.strictEqual(calculateTime(30, 30), 1);
  assert.strictEqual(calculateTime(59, 30), 1);
  assert.strictEqual(calculateTime(60, 30), 2);
});
