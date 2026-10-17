import test from "node:test";
import assert from "node:assert/strict";
import { dynamicTruncation, hotp } from "./hotp.ts";

// Appendix D - HOTP Algorithm: Test Values - https://www.rfc-editor.org/info/rfc4226/#page-32
test("spec tests", () => {
  const secret = Buffer.from("3132333435363738393031323334353637383930", "hex");
  assert.equal(hotp(secret, 0n), "755224");
  assert.equal(hotp(secret, 1n), "287082");
  assert.equal(hotp(secret, 2n), "359152");
  assert.equal(hotp(secret, 3n), "969429");
  assert.equal(hotp(secret, 4n), "338314");
  assert.equal(hotp(secret, 5n), "254676");
  assert.equal(hotp(secret, 6n), "287922");
  assert.equal(hotp(secret, 7n), "162583");
  assert.equal(hotp(secret, 8n), "399871");
  assert.equal(hotp(secret, 9n), "520489");
});

test("dynamicTruncation", () => {
  const byte = 0b11111111;
  dynamicTruncation(Buffer.from([byte]));
});
