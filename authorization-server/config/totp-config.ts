import type { OtpAuthUrlOptionsTotp } from "../../otp/otp-auth-url.ts";

export type TotpConfig = Required<
  Pick<OtpAuthUrlOptionsTotp, "issuer" | "algorithm" | "digits" | "period">
>;

/** Fixed development-only TOTP registration details. */
export const totpConfig: TotpConfig = {
  issuer: "OAuth Dev",
  // The following options below chosen for maximum compatibility.
  // Microsoft authenticator for example will only support 6 digits with a period of 30s.
  algorithm: "SHA1",
  digits: 6,
  period: 30,
};
