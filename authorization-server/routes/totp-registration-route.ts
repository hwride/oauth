import QRCode from "qrcode";
import type { FastifyInstance } from "fastify";
import { otpAuthUrl } from "../../otp/otp-auth-url.ts";
import { devTotpConfig } from "../config/totp-config.ts";
import { defaultUsers } from "../default-users.ts";
import type { MfaRegistration, UserRecord } from "../stores/user-store.ts";
import {
  createTimeBasedOneTimePasswordValidator,
  timeBasedOneTimePasswordCode,
} from "../../otp/time-based-one-time-password.ts";
import { fromBase32 } from "../../util/base-encoding.ts";

export function registerTotpRegistrationRoute(fastify: FastifyInstance) {
  fastify.get("/dev/totp-registration", async function (_, reply) {
    const userSection = await createUserSection();

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
      <tr><td>Issuer</td><td>${devTotpConfig.issuer}</td></tr>
      <tr><td>Algorithm</td><td>${devTotpConfig.algorithm}</td></tr>
      <tr><td>Period</td><td>${devTotpConfig.period}</td></tr>
      <tr><td>Digits</td><td>${devTotpConfig.digits}</td></tr>
    </table>
    
    <h2>Test user registration QR codes</h2>
    <p>Scan these QR codes with an authenticator app.</p>
    ${userSection}
  </body>
</html>`);
  });
}

async function createUserSection() {
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
        ...devTotpConfig,
        type: "totp",
        secretBase32: totpMfaReg.secretBase32,
        accountName: user.username,
      });
      const qrCodeSvg = await QRCode.toString(registrationUrl, {
        type: "svg",
        width: 240,
      });
      const { code: latestCode } = await timeBasedOneTimePasswordCode({
        key: fromBase32(totpMfaReg.secretBase32),
        codeType: "numeric", // otpauth:// URLs don't support providing alphanumeric as a type
        hashAlgorithm: devTotpConfig.algorithm,
        codeLength: devTotpConfig.digits,
        timeStepSeconds: devTotpConfig.period,
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
