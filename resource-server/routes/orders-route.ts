import type { FastifyInstance, FastifyReply } from "fastify";
import {
  type AccessTokenVerificationConfig,
  authenticateAccessToken,
} from "../utils/access-token-auth.ts";
import { hasAcr, hasRecentAuthTime, hasScope } from "../utils/token-utils.ts";
import type { ResourceServerConfig } from "../config.ts";
import type { OrderRecord, OrderStore } from "../stores/order-store.ts";

export function registerOrdersRoute(
  fastify: FastifyInstance,
  serverConfig: ResourceServerConfig,
  orderStore: OrderStore,
) {
  const verificationConfig: AccessTokenVerificationConfig = {
    resourceId: serverConfig.resourceIds.ordersApi,
    acceptedAccessTokenAlgorithms: serverConfig.acceptedAccessTokenAlgorithms,
    issuer: serverConfig.issuer,
    jwksUri: serverConfig.jwksUri,
  };

  fastify.get("/orders", async (request, reply) => {
    const authenticatedUser = await authenticateAccessToken(
      request,
      reply,
      verificationConfig,
    );

    // If user is undefined, the error response will have been handled by the util.
    if (!authenticatedUser) {
      return;
    }

    // https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1

    const hasScopeOrdersReadAny = hasScope(
      authenticatedUser.scope,
      "orders:read:any",
    );
    if (
      !hasScope(authenticatedUser.scope, "orders:read") &&
      !hasScopeOrdersReadAny
    ) {
      sendInsufficientScope(reply);
      return;
    }

    // Filter by scope.
    const ordersFromStore = hasScopeOrdersReadAny
      ? orderStore.getOrdersAll()
      : orderStore.getOrdersByUserId(authenticatedUser.sub);
    let orders: Array<OrderRecord | OrderRecordRedacted> = ordersFromStore;

    // Filter by acr value and authentication time.
    const hasHighValueOrderAuthentication = hasHighValueOrderAuth(
      authenticatedUser,
      serverConfig,
    );
    if (!hasHighValueOrderAuthentication) {
      orders = ordersFromStore.map(function (order) {
        return redactOrderForCollection(order, serverConfig);
      });
    }

    return { orders };
  });

  fastify.get("/orders/:id", async (request, reply) => {
    const authenticatedUser = await authenticateAccessToken(
      request,
      reply,
      verificationConfig,
    );

    if (!authenticatedUser) {
      return;
    }

    // Check the user has the correct scope to read orders.
    const hasScopeOrdersReadAny = hasScope(
      authenticatedUser.scope,
      "orders:read:any",
    );
    if (
      !hasScope(authenticatedUser.scope, "orders:read") &&
      !hasScopeOrdersReadAny
    ) {
      sendInsufficientScope(reply);
      return;
    }

    const hasHighValueOrderAuthentication = hasHighValueOrderAuth(
      authenticatedUser,
      serverConfig,
    );

    const requestedOrderId = (request.params as { id: string }).id;
    const order = orderStore.getOrderById(requestedOrderId);

    if (!order) {
      reply.status(404).send({ error: "not_found" });
      return;
    }

    // Deny the user if they don't own the order or have the read all orders scope.
    if (!hasScopeOrdersReadAny && order.userId !== authenticatedUser.sub) {
      reply.status(403).send({ error: "forbidden" });
      return;
    }

    // For high value orders check the user has the required acr and recent authentication time.
    if (
      order.valuePence >= serverConfig.highValueOrderPence &&
      !hasHighValueOrderAuthentication
    ) {
      sendInsufficientAcr(serverConfig, reply);
      return;
    }

    return { order };
  });
}

type OrderRecordRedacted = {
  orderId: string;
  redacted: true;
  acr_values: string;
};

/**
 * Does this user have the authentication context required for a high value order.
 */
function hasHighValueOrderAuth(
  authenticatedUser: { acr?: string; authTime?: number },
  serverConfig: ResourceServerConfig,
): boolean {
  return (
    hasAcr(authenticatedUser.acr, serverConfig.highValueOrderAcr) &&
    hasRecentAuthTime(
      authenticatedUser.authTime,
      serverConfig.highValueOrderMaxAuthAgeSeconds,
    )
  );
}

function redactOrderForCollection(
  order: OrderRecord,
  serverConfig: ResourceServerConfig,
): OrderRecord | OrderRecordRedacted {
  if (order.valuePence < serverConfig.highValueOrderPence) {
    return order;
  }

  // This redacted collection representation is our application-specific approach;
  // it is not defined by OAuth, OIDC, or RFC 9470.
  return {
    orderId: order.orderId,
    redacted: true,
    acr_values: serverConfig.highValueOrderAcr,
  };
}

function sendInsufficientScope(reply: FastifyReply) {
  reply
    .header(
      "WWW-Authenticate",
      'Bearer realm="resource-server", error="insufficient_scope", scope="orders:read"',
    )
    .status(403)
    .send({ error: "insufficient_scope" });
}

function sendInsufficientAcr(
  serverConfig: ResourceServerConfig,
  reply: FastifyReply,
) {
  reply
    .header(
      "WWW-Authenticate",
      `Bearer realm="resource-server", error="insufficient_user_authentication", acr_values="${serverConfig.highValueOrderAcr}", max_age="${serverConfig.highValueOrderMaxAuthAgeSeconds}"`,
    )
    .status(401)
    .send({ error: "insufficient_user_authentication" });
}
