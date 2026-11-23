import assert from "node:assert/strict";
import test from "node:test";
import { getAcrLevel2, hasAcr } from "./authentication-context-utils.ts";

test("getAcrLevel2 uses the issuer origin", () => {
  assert.equal(
    getAcrLevel2("https://issuer.example.test/oidc"),
    "https://issuer.example.test/acr/level-2",
  );
});

test("hasAcr matches an expected value in a space-separated acr_values request", () => {
  assert.equal(
    hasAcr(
      "https://issuer.example.test/acr/level-1 https://issuer.example.test/acr/level-2",
      "https://issuer.example.test/acr/level-2",
    ),
    true,
  );
  assert.equal(
    hasAcr(
      "https://issuer.example.test/acr/level-1",
      "https://issuer.example.test/acr/level-2",
    ),
    false,
  );
});
