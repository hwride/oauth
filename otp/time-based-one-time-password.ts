import { hmacOneTimePassword } from "./hmac-one-time-password.ts";

type TotpOptions = {
  key: ArrayBuffer;
  time?: Date;
  timeStep?: number;
  codeLength?: number;
  codeType?: CodeType;
};
type CodeType = "numeric" | "alphanumeric";

/**
 * Calculate a Time-Based One-Time Password.
 *
 * https://www.rfc-editor.org/info/rfc6238
 *
 * @param options.key - The key (secret) for the HMAC algorithm.
 * @param options.time - Optional time value to generate the code. Defaults to current time.
 * @param options.timeStep - Optional time step value in seconds. Defaults to 30s.
 * @param options.codeType - Whether to generate a number or alphanumeric OTP.
 * @param options.codeLength - The length of the OTP. Clamped between 6 and 10 for numeric codes,
 * and between 4 and 6 for alphanumeric codes.
 */
export async function timeBasedOneTimePassword(options: TotpOptions): Promise<{
  code: string;
}> {
  const date = options.time ?? new Date();
  const timeStep = options.timeStep ?? 30;
  const unixTime = toUnixTime(date);
  const time = calculateTime(unixTime, timeStep);

  // TODO: Adjust HOTP to support different hash functions.
  const hmacResults = await hmacOneTimePassword({
    ...options,
    counter: BigInt(time),
  });

  return { code: hmacResults.code };
}

export function calculateTime(unixTime: number, timeStepSeconds: number) {
  const t0 = 0;
  const secondsFromT0 = unixTime - t0;
  return Math.floor(secondsFromT0 / timeStepSeconds);
}

function toUnixTime(date: Date): number {
  return Math.floor(date.getTime() / 1000); // Date getTime() is ms not seconds.
}
