import assert from "node:assert/strict";
import test from "node:test";
import { hasAcr, hasRecentAuthTime, hasScope } from "./token-utils.ts";

test("tokenUtils returns true when the expected acr matches", function () {
  assert.equal(
    hasAcr(
      "https://orders-api.example.test/acr/level-2",
      "https://orders-api.example.test/acr/level-2",
    ),
    true,
  );
});

test("tokenUtils returns false when the acr does not exactly match", function () {
  assert.equal(
    hasAcr(
      "https://orders-api.example.test/acr/level-2 other",
      "https://orders-api.example.test/acr/level-2",
    ),
    false,
  );
});

test("tokenUtils returns false when acr is undefined", function () {
  assert.equal(
    hasAcr(undefined, "https://orders-api.example.test/acr/level-2"),
    false,
  );
});

test("tokenUtils returns true when auth time is less than the maximum age", function () {
  const nowSeconds = Math.floor(Date.now() / 1000);

  assert.equal(hasRecentAuthTime(nowSeconds - 59, 60), true);
});

test("tokenUtils returns false when auth time is at the maximum age", function () {
  const nowSeconds = Math.floor(Date.now() / 1000);

  assert.equal(hasRecentAuthTime(nowSeconds - 60, 60), false);
});

test("tokenUtils returns true when the expected scope is present", function () {
  assert.equal(hasScope("openid orders:read profile", "orders:read"), true);
});

test("tokenUtils returns false when the expected scope is missing", function () {
  assert.equal(hasScope("openid profile", "orders:read"), false);
});

test("tokenUtils returns false when scope is undefined", function () {
  assert.equal(hasScope(undefined, "orders:read"), false);
});

test("tokenUtils matches whole scope values only", function () {
  assert.equal(
    hasScope("orders:read:any notorders:read", "orders:read"),
    false,
  );
});

test("tokenUtils handles repeated whitespace between scopes", function () {
  assert.equal(hasScope("openid   orders:read\nprofile", "orders:read"), true);
});
