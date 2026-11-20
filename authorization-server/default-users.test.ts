import assert from "node:assert/strict";
import test from "node:test";
import {
  adminUserId,
  defaultUsers,
  janeUserId,
  testUserId,
} from "./default-users.ts";
import { createUserStore } from "./stores/user-store.ts";

test("defaultUsers returns the seeded test users", function () {
  assert.deepEqual(defaultUsers(), [
    {
      userId: adminUserId,
      username: "admin",
      password: "password",
      name: "John Wick",
      roles: ["admin"],
      mfaRegistrations: [
        {
          type: "TOTP",
          secretBase32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        },
      ],
    },
    {
      userId: testUserId,
      username: "user",
      password: "password",
      name: "John Smith",
      roles: ["customer"],
      mfaRegistrations: [
        {
          type: "TOTP",
          secretBase32: "JXN44HP4T27N7PMSXH5L6DOUZ36ADZGV",
        },
      ],
    },
    {
      userId: janeUserId,
      username: "jane",
      password: "password",
      name: "Jane Smith",
      given_name: "Jane",
      family_name: "Smith",
      middle_name: "Elizabeth",
      nickname: "Janie",
      preferred_username: "jane",
      profile: "https://example.test/users/jane",
      picture: "https://example.test/images/jane-smith.jpg",
      website: "https://jane.example.test",
      email: "jane@example.test",
      email_verified: true,
      gender: "female",
      birthdate: "1990-01-02",
      zoneinfo: "Europe/London",
      locale: "en-GB",
      phone_number: "+442079460018",
      phone_number_verified: true,
      address: {
        formatted: "10 Example Street\nLondon SW1A 1AA\nUnited Kingdom",
        street_address: "10 Example Street",
        locality: "London",
        region: "London",
        postal_code: "SW1A 1AA",
        country: "GB",
      },
      updated_at: 1_700_000_000,
    },
  ]);
});

test("defaultUsers can seed a user store", function () {
  const userStore = createUserStore(defaultUsers());

  const admin = userStore.loadUserByUsername("admin");
  const user = userStore.loadUserByUsername("user");
  const jane = userStore.loadUserByUsername("jane");

  assert.notEqual(admin, undefined);
  assert.notEqual(user, undefined);
  assert.notEqual(jane, undefined);
  assert.deepEqual(admin.roles, ["admin"]);
  assert.deepEqual(user.roles, ["customer"]);
  assert.equal(jane.allowedScopes, undefined);
  assert.equal(jane.roles, undefined);
  assert.equal(userStore.loadUserById(adminUserId), admin);
  assert.equal(userStore.loadUserById(testUserId), user);
  assert.equal(userStore.loadUserById(janeUserId), jane);
});
