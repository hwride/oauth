import assert from "node:assert/strict";
import test from "node:test";
import { getUserClaims } from "./oidc-utils.ts";

test("getUserClaims returns standard claims for their OIDC scopes", function () {
  const user = {
    userId: "user-id",
    username: "user",
    password: "password",
    name: "Jane Doe",
    given_name: "Jane",
    family_name: "Doe",
    middle_name: "Q",
    nickname: "Janie",
    preferred_username: "jane.doe",
    profile: "https://example.test/jane",
    picture: "https://example.test/jane.jpg",
    website: "https://example.test",
    email: "jane@example.test",
    email_verified: true,
    gender: "female",
    birthdate: "1990-01-02",
    zoneinfo: "Europe/London",
    locale: "en-GB",
    phone_number: "+441234567890",
    phone_number_verified: true,
    address: {
      formatted: "1 Example Street, London",
      street_address: "1 Example Street",
      locality: "London",
      region: "London",
      postal_code: "SW1A 1AA",
      country: "GB",
    },
    updated_at: 1_700_000_000,
  };

  assert.deepEqual(getUserClaims(user, "openid profile email address phone"), {
    name: "Jane Doe",
    given_name: "Jane",
    family_name: "Doe",
    middle_name: "Q",
    nickname: "Janie",
    preferred_username: "jane.doe",
    profile: "https://example.test/jane",
    picture: "https://example.test/jane.jpg",
    website: "https://example.test",
    email: "jane@example.test",
    email_verified: true,
    gender: "female",
    birthdate: "1990-01-02",
    zoneinfo: "Europe/London",
    locale: "en-GB",
    phone_number: "+441234567890",
    phone_number_verified: true,
    address: {
      formatted: "1 Example Street, London",
      street_address: "1 Example Street",
      locality: "London",
      region: "London",
      postal_code: "SW1A 1AA",
      country: "GB",
    },
    updated_at: 1_700_000_000,
  });
});

test("getUserClaims omits claims without a matching scope", function () {
  const user = {
    userId: "user-id",
    username: "user",
    password: "password",
    name: "Jane Doe",
    email: "jane@example.test",
  };

  assert.deepEqual(getUserClaims(user, "openid"), {});
});
