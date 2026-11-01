import test from "node:test";
import assert from "node:assert/strict";
import { otpAuthUrl } from "./otp-auth-url.ts";

const secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

test("totp - no optional params", async () => {
  assert.strictEqual(
    otpAuthUrl({
      type: "totp",
      accountName: "test@example.com",
      secretBase32,
    }),
    `otpauth://totp/test%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`,
  );
});

test("totp with optional params", async () => {
  assert.strictEqual(
    otpAuthUrl({
      type: "totp",
      issuer: "example.com",
      accountName: "test@example.com",
      secretBase32,
      algorithm: "SHA512",
      digits: 6,
      period: 30,
    }),
    `otpauth://totp/example.com%3Atest%40example.com?issuer=example.com&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA512&digits=6&period=30`,
  );
});

test("totp with a distinct issuer query param", async () => {
  assert.strictEqual(
    otpAuthUrl({
      type: "totp",
      issuer: "OAuth Dev",
      issuerParam: "issuer.example.test",
      accountName: "test@example.com",
      secretBase32,
    }),
    `otpauth://totp/OAuth%20Dev%3Atest%40example.com?issuer=issuer.example.test&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`,
  );
});

test("hotp with optional params", async () => {
  assert.strictEqual(
    otpAuthUrl({
      type: "hotp",
      issuer: "example.com",
      accountName: "test@example.com",
      secretBase32,
      algorithm: "SHA256",
      digits: 8,
      counter: 50,
    }),
    `otpauth://hotp/example.com%3Atest%40example.com?issuer=example.com&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&counter=50`,
  );
});
