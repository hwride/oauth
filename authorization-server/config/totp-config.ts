import type { OtpAuthUrlOptionsTotp } from "../../otp/otp-auth-url.ts";
import type { TotpOptionsValidator } from "../../otp/time-based-one-time-password.ts";

export type TotpConfig = Required<
  Pick<OtpAuthUrlOptionsTotp, "issuer" | "algorithm" | "digits" | "period">
> &
  Required<Pick<TotpOptionsValidator, "allowedTimeSteps">>;

/** Fixed development-only TOTP registration details. */
export const totpConfig: TotpConfig = {
  issuer: "OAuth Dev",
  // The following options below chosen for maximum compatibility.
  // Microsoft authenticator for example will only support 6 digits with a period of 30s.
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  // Accept the current step and one previous 30-second step for clock skew.
  allowedTimeSteps: 2,
};
