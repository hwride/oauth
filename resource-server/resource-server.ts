import Fastify, { type FastifyInstance } from "fastify";
import {
  getResourceServerConfig,
  type ResourceServerConfig,
} from "./config.ts";
import { registerHomeRoute } from "./routes/home-route.ts";
import { registerOrdersRoute } from "./routes/orders-route.ts";
import { registerProductsRoute } from "./routes/products-route.ts";
import { createDefaultOrderStore } from "./stores/order-store.ts";
import { createDefaultProductStore } from "./stores/product-store.ts";

export const defaultResourceServerPort = 5000;

if (import.meta.main) {
  main();
}

export async function main() {
  const serverConfig = await getResourceServerConfig();
  const fastify = createServer(serverConfig);

  try {
    await fastify.listen({
      port: getResourceServerPort(),
    });
    fastify.log.info("Resource server is booted");
    return fastify;
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

export function createServer(serverConfig: ResourceServerConfig) {
  const fastify = Fastify({
    logger: {
      transport: {
        target: "pino-pretty",
        options: {
          translateTime: "HH:MM:ss Z",
          ignore: "pid,hostname",
        },
      },
    },
    disableRequestLogging: true,
  });

  logResourceServerConfig(fastify, serverConfig);

  const orderStore = createDefaultOrderStore();
  const productStore = createDefaultProductStore();

  registerHomeRoute(fastify);
  registerOrdersRoute(fastify, serverConfig, orderStore);
  registerProductsRoute(fastify, serverConfig, productStore);

  return fastify;
}

function logResourceServerConfig(
  fastify: FastifyInstance,
  serverConfig: ResourceServerConfig,
) {
  fastify.log.info(
    {
      port: getResourceServerPort(),
      resourceIds: serverConfig.resourceIds,
      acceptedAccessTokenAlgorithms: serverConfig.acceptedAccessTokenAlgorithms,
      authServerBase: serverConfig.authServerBase,
      issuer: serverConfig.issuer,
      jwksUri: serverConfig.jwksUri,
    },
    "Resource server config",
  );
}

function getResourceServerPort() {
  return Number(process.env.RESOURCE_SERVER_PORT ?? defaultResourceServerPort);
}
