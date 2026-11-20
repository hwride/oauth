import assert from "node:assert/strict";
import test from "node:test";
import { hasScope, parseScopeStr } from "./oauth-utils.ts";

test("parseScopeStr returns scope values as a set", function () {
  assert.deepEqual(
    parseScopeStr("openid profile  email\nprofile"),
    new Set(["openid", "profile", "email"]),
  );
});

test("parseScopeStr returns an empty set for non-string values", function () {
  assert.deepEqual(parseScopeStr(undefined), new Set());
  assert.deepEqual(parseScopeStr(null), new Set());
});

test("hasScope checks for a complete scope value", function () {
  assert.equal(hasScope("openid profile", "profile"), true);
  assert.equal(hasScope("openid profile", "pro"), false);
  assert.equal(hasScope(undefined, "profile"), false);
});
