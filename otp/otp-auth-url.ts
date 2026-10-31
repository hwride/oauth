export type OtpAuthUrlOptions = OtpAuthUrlOptionsTotp | OtpAuthUrlOptionsHotp;

export type OtpAuthUrlOptionsHotp = OtpAuthUrlOptionsShared & {
  /** The type of OTP auth - Time-Based One-Time Password or HMAC One-Time Password. */
  type: "hotp";
  /** Initial counter to start HOTP generation at. */
  counter: number;
};
export type OtpAuthUrlOptionsTotp = OtpAuthUrlOptionsShared & {
  /** The type of OTP auth - Time-Based One-Time Password or HMAC One-Time Password. */
  type: "totp";
  /** How many seconds a TOTP code is valid for. Default is 30s. */
  period?: number;
};

type OtpAuthUrlOptionsShared = {
  /**
   * Optional issuer of the account. Allows disambiguation of different account names.
   * Recommended to be the domain of the site or app e.g. example.com.
   * The password manager uses this field to suggest credentials when setting up a new code generator.
   * */
  issuer?: string;
  /** The account name, e.g. test@example.com. */
  accountName: string;
  /** A secret value encoded in Base32. Secrets should be at least 160 bits. */
  secretBase32: string;
  /** Algorithm used to generate OTPs. */
  algorithm?: "SHA1" | "SHA256" | "SHA512";
  /** How many digits this OTP uses. Default is 6. */
  digits?: 6 | 8;
};

/**
 * Generate an otpauth:// URL for registering OTP details with an Authenticator.
 *
 * otpauth://TYPE/LABEL?PARAMETERS
 */
export function otpAuthUrl(options: OtpAuthUrlOptions): string {
  // Create label
  const label = options.issuer
    ? `${options.issuer}:${options.accountName}`
    : options.accountName;
  const labelEncoded = encodeURIComponent(label);

  // Create URL
  const url = new URL(`otpauth://${options.type}/${labelEncoded}`);

  // Set URL params
  const setOptionalParamHelper = (name: keyof OtpAuthUrlOptionsTotp) => {
    if (options[name]) {
      url.searchParams.set(name, String(options[name]));
    }
  };

  setOptionalParamHelper("issuer");
  setOptionalParamHelper("secretBase32");
  setOptionalParamHelper("algorithm");
  setOptionalParamHelper("digits");

  if (options.type === "totp") {
    setOptionalParamHelper("period");
  } else {
    url.searchParams.set("counter", String(options.counter));
  }

  return url.toString();
}

/*
  Other resources:
  - https://www.ietf.org/archive/id/draft-linuxgemini-otpauth-uri-00.html (note this expired)
  - https://otpauth.dev/
  - https://github.com/google/google-authenticator/wiki/Key-Uri-Format
  - https://developer.apple.com/documentation/authenticationservices/securing-logins-with-icloud-keychain-verification-codes
 */
