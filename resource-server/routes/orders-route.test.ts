import assert from "node:assert/strict";
import type { OutgoingHttpHeaders } from "node:http";
import test from "node:test";
import { createServer } from "../resource-server.ts";
import { adminUserId, janeUserId, testUserId } from "../stores/order-store.ts";
import {
  createMockAuthServer,
  type MockAuthServer,
} from "../test-utils/mock-auth-server.ts";

const ordersApiResourceId = "https://orders-api.example.test";
const productsApiResourceId = "https://products-api.example.test";
const highValueOrderAcr = "https://orders-api.example.test/acr/level-2";
const highValueOrderMaxAuthAgeSeconds = 60;

test("GET /orders returns orders for the authenticated user from the order store", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 200);
    assert.equal(
      response.headers["content-type"],
      "application/json; charset=utf-8",
    );

    const body = response.json() as {
      orders: Array<{ orderId: string; userId: string; valuePence: number }>;
    };

    assert.deepEqual(body.orders, [
      { orderId: "order-001", userId: testUserId, valuePence: 100 },
      {
        // If user does not have required ACR orders are redacted.
        orderId: "order-002",
        redacted: true,
        acr_values: highValueOrderAcr,
      },
    ]);
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns full orders when the access token has the required acr", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      acr: highValueOrderAcr,
      auth_time: Math.floor(Date.now() / 1000),
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), {
      orders: [
        { orderId: "order-001", userId: testUserId, valuePence: 100 },
        { orderId: "order-002", userId: testUserId, valuePence: 10000 },
      ],
    });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders redacts high-value orders when authentication is too old", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      acr: highValueOrderAcr,
      auth_time:
        Math.floor(Date.now() / 1000) - highValueOrderMaxAuthAgeSeconds,
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), {
      orders: [
        { orderId: "order-001", userId: testUserId, valuePence: 100 },
        {
          orderId: "order-002",
          redacted: true,
          acr_values: highValueOrderAcr,
        },
      ],
    });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns all orders when the access token includes orders:read:any scope", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: adminUserId,
      scope: "orders:read:any",
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 200);

    const body = response.json() as {
      orders: Array<{ orderId: string; userId: string; valuePence: number }>;
    };

    assert.deepEqual(body.orders, [
      { orderId: "order-001", userId: testUserId, valuePence: 100 },
      {
        orderId: "order-002",
        redacted: true,
        acr_values: highValueOrderAcr,
      },
      { orderId: "order-003", userId: janeUserId, valuePence: 500 },
      { orderId: "order-004", userId: janeUserId, valuePence: 2000 },
    ]);
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders/:id returns an individual order when it is owned by the authenticated user", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders/order-001",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), {
      order: { orderId: "order-001", userId: testUserId, valuePence: 100 },
    });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders/:id returns 401 when a high-value order lacks the required acr", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders/order-002",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 401);
    assert.equal(
      getHeader(response.headers, "www-authenticate"),
      `Bearer realm="resource-server", error="insufficient_user_authentication", acr_values="${highValueOrderAcr}", max_age="${highValueOrderMaxAuthAgeSeconds}"`,
    );
    assert.deepEqual(response.json(), {
      error: "insufficient_user_authentication",
    });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders/:id returns a high-value order when the access token has the required acr", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      acr: highValueOrderAcr,
      auth_time: Math.floor(Date.now() / 1000),
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders/order-002",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), {
      order: { orderId: "order-002", userId: testUserId, valuePence: 10000 },
    });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders/:id returns 401 when authentication is too old", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      acr: highValueOrderAcr,
      auth_time:
        Math.floor(Date.now() / 1000) - highValueOrderMaxAuthAgeSeconds,
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders/order-002",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 401);
    assert.equal(
      getHeader(response.headers, "www-authenticate"),
      `Bearer realm="resource-server", error="insufficient_user_authentication", acr_values="${highValueOrderAcr}", max_age="${highValueOrderMaxAuthAgeSeconds}"`,
    );
    assert.deepEqual(response.json(), {
      error: "insufficient_user_authentication",
    });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders/:id rejects a high-value order when the acr does not exactly match", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      acr: `${highValueOrderAcr} other`,
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders/order-002",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 401);
    assert.deepEqual(response.json(), {
      error: "insufficient_user_authentication",
    });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders/:id returns another user's order when the access token includes orders:read:any scope", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: adminUserId,
      scope: "orders:read:any",
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders/order-003",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), {
      order: { orderId: "order-003", userId: janeUserId, valuePence: 500 },
    });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders/:id returns 403 when the order is owned by a different user", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders/order-003",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 403);
    assert.deepEqual(response.json(), { error: "forbidden" });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders/:id returns 404 when no order with the given id exists", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders/order-999",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 404);
    assert.deepEqual(response.json(), { error: "not_found" });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 403 when the access token does not include orders:read scope", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "openid profile",
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 403);
    assert.equal(
      getHeader(response.headers, "www-authenticate"),
      `Bearer realm="resource-server", error="insufficient_scope", scope="orders:read"`,
    );
    assert.deepEqual(response.json(), { error: "insufficient_scope" });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders/:id returns 403 when the access token does not include orders:read scope", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: janeUserId,
      scope: "openid profile",
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders/order-003",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 403);
    assert.equal(
      getHeader(response.headers, "www-authenticate"),
      `Bearer realm="resource-server", error="insufficient_scope", scope="orders:read"`,
    );
    assert.deepEqual(response.json(), { error: "insufficient_scope" });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 401 when authorization header is missing", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
    });

    assert.equal(response.statusCode, 401);
    assert.equal(
      getHeader(response.headers, "www-authenticate"),
      `Bearer realm="resource-server"`,
    );
    assert.equal(response.body, "");
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 401 without error details when auth scheme is unsupported", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: "Basic abc123",
      },
    });

    assert.equal(response.statusCode, 401);
    assert.equal(
      getHeader(response.headers, "www-authenticate"),
      `Bearer realm="resource-server"`,
    );
    assert.equal(response.body, "");
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 401 when token verification fails", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: "Bearer not-a-jwt",
      },
    });

    assert.equal(response.statusCode, 401);
    assert.match(
      getHeader(response.headers, "www-authenticate"),
      /ERR_JWS_INVALID/,
    );
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 401 when issuer does not match", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      iss: "https://different-issuer.example.test",
      sub: testUserId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 401);
    assert.match(
      getHeader(response.headers, "www-authenticate"),
      /ERR_JWT_CLAIM_VALIDATION_FAILED/,
    );
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 401 when aud is missing", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 401);
    assert.match(
      getHeader(response.headers, "www-authenticate"),
      /ERR_JWT_CLAIM_VALIDATION_FAILED/,
    );
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 401 when aud does not match", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      aud: "invalid-aud",
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 401);
    assert.match(
      getHeader(response.headers, "www-authenticate"),
      /ERR_JWT_CLAIM_VALIDATION_FAILED/,
    );
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders rejects expired tokens", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      exp: Math.floor(Date.now() / 1000) - 10,
      nbf: Math.floor(Date.now() / 1000) - 60,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 401);
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

function createTestResourceServer(authServer: MockAuthServer) {
  return createServer({
    resourceIds: {
      ordersApi: ordersApiResourceId,
      productsApi: productsApiResourceId,
    },
    highValueOrderPence: 100 * 50,
    highValueOrderAcr,
    highValueOrderMaxAuthAgeSeconds,
    acceptedAccessTokenAlgorithms: ["RS256"],
    authServerBase: authServer.authServerBase,
    issuer: authServer.issuer,
    jwksUri: authServer.jwksUri,
  });
}

function getHeader(headers: OutgoingHttpHeaders, headerName: string): string {
  const header = headers[headerName];

  if (Array.isArray(header)) {
    return header.join(", ");
  }

  return header === undefined ? "" : String(header);
}
