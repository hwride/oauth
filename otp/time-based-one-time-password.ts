import {
  type CodeType,
  hmacOneTimePassword,
} from "./hmac-one-time-password.ts";

type TotpOptions = TotpOptionsCode & {
  /** The code to validate. */
  expectedCode: string;
  /** How many time steps to consider valid. Defaults to 1. */
  allowedTimeSteps?: number;
};

type TotpOptionsCode = {
  /** The key (secret) for the HMAC algorithm. */
  key: ArrayBuffer;
  /** Optional time value to generate the code. Defaults to current time. */
  time?: Date;
  /** Optional time step value in seconds. Defaults to 30s. */
  timeStep?: number;
  /** Whether to generate a number or alphanumeric OTP. */
  codeType?: CodeType;
  /**
   * The length of the OTP. Clamped between 6 and 10 for numeric codes,
   * and between 4 and 6 for alphanumeric codes.
   */
  codeLength?: number;
};

// TODO: Allow remembering of already used codes
// TODO: Adjust HOTP to support different hash functions.

/**
 * Validate a Time-Based One-Time Password value.
 *
 * https://www.rfc-editor.org/info/rfc6238
 */
export async function timeBasedOneTimePassword(options: TotpOptions): Promise<{
  /** If the given code is valid. */
  isValid: boolean;
  /** The code that actually matched in the end. */
  matchingCode?: string;
}> {
  const optionsRequired = {
    ...options,
    time: options.time ?? new Date(),
    timeStep: options.timeStep ?? 30,
  };
  const allowedTimeSteps = options.allowedTimeSteps ?? 1;

  // Loop through all the allowed time steps starting from time, until we find a matching code or we fail to match.
  for (let i = 0; i < allowedTimeSteps; i += 1) {
    const stepTime = new Date(optionsRequired.time);
    stepTime.setSeconds(
      optionsRequired.time.getSeconds() + optionsRequired.timeStep * i,
    );
    const { code } = await timeBasedOneTimePasswordCode({
      ...optionsRequired,
      time: stepTime,
    });
    if (code === options.expectedCode) {
      return {
        isValid: true,
        matchingCode: code,
      };
    }
  }

  return { isValid: false };
}

/**
 * Calculate a Time-Based One-Time Password.
 *
 * https://www.rfc-editor.org/info/rfc6238
 */
export async function timeBasedOneTimePasswordCode(
  options: TotpOptionsCode,
): Promise<{
  code: string;
}> {
  const date = options.time ?? new Date();
  const timeStep = options.timeStep ?? 30;
  const unixTime = toUnixTime(date);
  const time = calculateTime(unixTime, timeStep);

  const hmacResults = await hmacOneTimePassword({
    ...options,
    counter: BigInt(time),
  });

  return { code: hmacResults.code };
}

/**
 * Calculate the time value from unix time and time step value.
 *
 * See https://www.rfc-editor.org/info/rfc6238/#section-4.2
 * @param unixTime The unix time (in seconds) to generate a code for.
 * @param timeStepSeconds The time step length in seconds.
 */
export function calculateTime(unixTime: number, timeStepSeconds: number) {
  const t0 = 0;
  const secondsFromT0 = unixTime - t0;
  return Math.floor(secondsFromT0 / timeStepSeconds);
}

function toUnixTime(date: Date): number {
  return Math.floor(date.getTime() / 1000); // Date getTime() is ms not seconds.
}
