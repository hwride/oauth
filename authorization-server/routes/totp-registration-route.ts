import QRCode from "qrcode";
import type { FastifyInstance } from "fastify";
import { otpAuthUrl } from "../../otp/otp-auth-url.ts";
import { totpConfig } from "../config/totp-config.ts";
import { defaultUsers } from "../default-users.ts";
import type { ServerConfig } from "../config/server-config.ts";
import type { MfaRegistration, UserRecord } from "../stores/user-store.ts";
import {
  createTimeBasedOneTimePasswordValidator,
  timeBasedOneTimePasswordCode,
} from "../../otp/time-based-one-time-password.ts";
import { fromBase32 } from "../../util/base-encoding.ts";

export function registerTotpRegistrationRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
) {
  fastify.get("/dev/totp-registration", async function (_, reply) {
    const issuerParam = new URL(serverConfig.issuer).hostname;
    const userSection = await createUserSection(issuerParam);

    return reply.type("text/html; charset=utf-8").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>TOTP registration</title>
  </head>
  <body>
    <h1>Time-Base One-Time Password (TOTP) Registration</h1>
    
    <h2>Server TOTP config</h2>
    <table>
      <tr><td>Issuer</td><td>${totpConfig.issuer}</td></tr>
      <tr><td>Algorithm</td><td>${totpConfig.algorithm}</td></tr>
      <tr><td>Period</td><td>${totpConfig.period}</td></tr>
      <tr><td>Digits</td><td>${totpConfig.digits}</td></tr>
    </table>
    
    <h2>Test user registration QR codes</h2>
    <p>Scan these QR codes with an authenticator app.</p>
    ${userSection}
  </body>
</html>`);
  });
}

async function createUserSection(issuerParam: string) {
  const defaultUsersWithTotpMfa: {
    user: UserRecord;
    totpMfaReg: MfaRegistration;
    registrationUrl: string;
    qrCodeSvg: string;
    latestCode: string;
  }[] = [];
  for (const user of defaultUsers()) {
    const totpMfaReg = user.mfaRegistrations?.find((r) => r.type === "TOTP");
    if (totpMfaReg) {
      const registrationUrl = otpAuthUrl({
        ...totpConfig,
        type: "totp",
        secretBase32: totpMfaReg.secretBase32,
        accountName: user.username,
        issuerParam,
      });
      const qrCodeSvg = await QRCode.toString(registrationUrl, {
        type: "svg",
        width: 240,
      });
      const { code: latestCode } = await timeBasedOneTimePasswordCode({
        key: fromBase32(totpMfaReg.secretBase32),
        codeType: "numeric", // otpauth:// URLs don't support providing alphanumeric as a type
        hashAlgorithm: totpConfig.algorithm,
        codeLength: totpConfig.digits,
        timeStepSeconds: totpConfig.period,
      });
      defaultUsersWithTotpMfa.push({
        user,
        totpMfaReg,
        registrationUrl,
        qrCodeSvg,
        latestCode,
      });
    }
  }

  return defaultUsersWithTotpMfa
    .map(({ user, registrationUrl, qrCodeSvg, latestCode }) => {
      return `<div>
      <h3>User ${user.username}</h3>
      <p>${registrationUrl}</p>
      <p>Latest code: ${latestCode}</p>
${qrCodeSvg}
</div>`;
    })
    .join("\n");
}
