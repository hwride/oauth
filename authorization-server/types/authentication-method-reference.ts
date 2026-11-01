/**
 * Authentication Method Reference (AMR) values currently emitted by this server.
 * This is intentionally not an exhaustive list; RFC 8176 defines additional values.
 * https://datatracker.ietf.org/doc/html/rfc8176
 */
export type AuthenticationMethodReference = "pwd" | "mfa" | "otp";
