import type { OtpAuthUrlOptionsTotp } from "../../otp/otp-auth-url.ts";

export type TotpConfig = Required<
  Pick<OtpAuthUrlOptionsTotp, "issuer" | "algorithm" | "digits" | "period">
>;

/** Fixed development-only TOTP registration details. */
export const devTotpConfig: TotpConfig = {
  issuer: "OAuth Dev",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
};
