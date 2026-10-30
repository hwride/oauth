import type { OtpAuthUrlOptionsTotp } from "../../otp/otp-auth-url.ts";

export type DevTotpConfig = Required<Omit<OtpAuthUrlOptionsTotp, "type">>;

/** Fixed development-only TOTP registration details. */
export const devTotpConfig: DevTotpConfig = {
  issuer: "OAuth Dev",
  accountName: "dev@example.test",
  // 160-bit Base32 secret. Keep fixed so the dev registration survives restarts.
  secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
};
