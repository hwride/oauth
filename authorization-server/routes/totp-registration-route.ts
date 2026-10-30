import QRCode from "qrcode";
import type { FastifyInstance } from "fastify";
import { otpAuthUrl } from "../../otp/otp-auth-url.ts";
import { devTotpConfig } from "../config/dev-totp-config.ts";

export function registerTotpRegistrationRoute(fastify: FastifyInstance) {
  fastify.get("/dev/totp-registration", async function (_, reply) {
    const config = devTotpConfig;
    const registrationUrl = otpAuthUrl({
      type: "totp",
      ...config,
    });
    const qrCodeSvg = await QRCode.toString(registrationUrl, {
      type: "svg",
      width: 240,
    });
    return reply.type("text/html; charset=utf-8").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>TOTP registration</title>
  </head>
  <body>
    <h1>TOTP registration</h1>
    <p>Scan this QR code with an authenticator app.</p>
    ${qrCodeSvg}
    <p>Registration URL: <code>${escapeHtml(registrationUrl)}</code></p>
  </body>
</html>`);
  });
}

function escapeHtml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
