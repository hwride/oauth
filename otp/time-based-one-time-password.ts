import {
  type CodeType,
  type HashAlgorithm,
  hmacOneTimePassword,
  supportedHashAlgorithms,
} from "./hmac-one-time-password.ts";

type TotpOptionsShared = {
  /** The key (secret) for the HMAC algorithm. */
  key: ArrayBuffer;
  /** Optional time step value in seconds. Defaults to 30s. */
  timeStepSeconds?: number;
  /** Whether to generate a number or alphanumeric OTP. */
  codeType?: CodeType;
  /**
   * The length of the OTP. Clamped between 6 and 10 for numeric codes,
   * and between 4 and 6 for alphanumeric codes.
   */
  codeLength?: number;
  /** Default to SHA-512 if unspecified. */
  hashAlgorithm?: HashAlgorithm;
};

export type TotpOptionsValidator = TotpOptionsShared & {
  /** How many time steps to consider valid. It considers steps in the past valid, not in the future. Defaults to 1. */
  allowedTimeSteps?: number;
  /**
   * Ability to set a custom store for storing used codes. This is needed to prevent code re-use.
   *
   * By default uses an in-memory store - not suitable for production use as this will lose all data on service restart
   * and will not normalise code storage across > 1 process.
   */
  customCodeStoreCreator?: CodeStoreCreator;
};

/**
 * Validator which takes an expected TOTP code and checks if it's valid. Works according to {@see TotpOptionsValidator}
 * config.
 */
export type TotpValidator = {
  validate: (
    expectedCode: string,
    { time }?: Pick<TotpOptionsCode, "time">,
  ) => Promise<{ isValid: boolean }>;
};

export type CodeStoreCreator = (
  /**
   * You can use allowed time steps to perform clearing of entries that are no longer valid. You never need to store
   * more codes than the number of allowed time steps. But ensure you remove oldest codes first.
   */
  options: Required<Pick<TotpOptionsValidator, "allowedTimeSteps">>,
) => CodeStore;
export type CodeStore = {
  /**
   * Check if a key has been used. Return duplicate if it has been used already, or accepted if it's new.
   * If accepted should store the code for the next check. This should all be performed as an atomic operation to
   * ensure concurrent use behaves correctly.
   */
  check: (opts: {
    /**
     * Key to store in the cache. Technically: <time-step-number>:<totp-code>
     */
    key: string;
    /**
     * The time step number, higher == later. You may use this information for cache eviction to ensure oldest
     * are evicted first. */
    timeStepNumber: number;
  }) => Promise<"duplicate" | "accepted">;
};

export type TotpOptionsCode = TotpOptionsShared & {
  /** Optional time value to generate the code. Defaults to current time. */
  time?: Date;
};

const defaultTimeStepSeconds = 30;
const defaultAllowedTimeSteps = 1;

// TODO: Adjust HOTP to support different hash functions.

/**
 * In-memory code store. Not suitable for production.
 */
const createMemoryCodeStore: CodeStoreCreator = (options) => {
  const usedCodes: { key: string; timeStepNumber: number }[] = [];

  return {
    async check({ key, timeStepNumber }) {
      if (usedCodes.some((usedCode) => usedCode.key === key)) {
        return "duplicate";
      } else {
        usedCodes.push({ key, timeStepNumber });

        // Remove codes that could never be valid anymore anyway as we're passed that time.
        usedCodes.sort((a, b) => b.timeStepNumber - a.timeStepNumber);
        usedCodes.splice(options.allowedTimeSteps);
        return "accepted";
      }
    },
  };
};

/**
 * Creates a Time-Base One-Time Password validator.
 */
export function createTimeBasedOneTimePasswordValidator(
  options: TotpOptionsValidator,
): TotpValidator {
  // Defaults
  const allowedTimeSteps = options.allowedTimeSteps ?? defaultAllowedTimeSteps;
  const optionsGenCode: TotpOptionsCode = {
    ...options,
    timeStepSeconds: options.timeStepSeconds ?? defaultTimeStepSeconds,
  };

  // Validation.
  if (
    !Number.isInteger(optionsGenCode.timeStepSeconds) ||
    optionsGenCode.timeStepSeconds < 1
  ) {
    throw new Error("Invalid value for timeStepSeconds, must be > 0");
  }

  if (!Number.isInteger(allowedTimeSteps) || allowedTimeSteps < 1) {
    throw new Error("Invalid value for allowedTimeSteps, must be > 0");
  }

  // Check hash algorithm.
  optionsGenCode.hashAlgorithm ??= "SHA-512";
  if (!supportedHashAlgorithms.includes(optionsGenCode.hashAlgorithm)) {
    throw new Error(
      `Unsupported hash algorithm. Supported: ${supportedHashAlgorithms}`,
    );
  }

  // Create the code store.
  const codeStoreCreator =
    options.customCodeStoreCreator ?? createMemoryCodeStore;
  const codeStore = codeStoreCreator({
    allowedTimeSteps,
  });

  const totpValidator: TotpValidator = {
    validate: async (
      expectedCode,
      { time } = {},
    ): Promise<{ isValid: boolean }> => {
      time ??= new Date();
      const baseUnixTime = toUnixTime(time);

      // Loop through all the allowed time steps starting from time, until we find a matching code or we fail to match.
      for (let timeStep = -allowedTimeSteps + 1; timeStep <= 0; timeStep += 1) {
        // Calculate time for this step.
        // Do calculation in Unix time to avoid any DST weirdness using Date.setSeconds
        const stepUnixTime =
          baseUnixTime + optionsGenCode.timeStepSeconds * timeStep;
        const stepUnixTimeDate = fromUnixTime(stepUnixTime);

        // Get the code for this step.
        const { code } = await timeBasedOneTimePasswordCode({
          ...optionsGenCode,
          time: stepUnixTimeDate,
        });

        // Didn't match, try next step.
        if (code !== expectedCode) {
          continue;
        }

        // Did match, check this code isn't being re-used.
        // Make sure we save a combination of step time + code, in case two time values happen to generate the same code
        // we don't want to block use for the other time value.
        const timeStepNum = calculateTimeStepNumber(
          stepUnixTime,
          optionsGenCode.timeStepSeconds,
        );
        const codeStoreKey = `${timeStepNum}:${code}`;
        const codeStoreCheckResult = await codeStore.check({
          key: codeStoreKey,
          timeStepNumber: timeStepNum,
        });
        if (codeStoreCheckResult === "duplicate") {
          continue;
        }

        // Code is valid.
        return { isValid: true };
      }

      return { isValid: false };
    },
  };
  return totpValidator;
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
  const timeStepSeconds = options.timeStepSeconds ?? defaultTimeStepSeconds;
  if (!Number.isInteger(timeStepSeconds) || timeStepSeconds < 1) {
    throw new Error("Invalid value for timeStepSeconds, must be > 0");
  }

  const date = options.time ?? new Date();
  const unixTime = toUnixTime(date);
  const timeStepNum = calculateTimeStepNumber(unixTime, timeStepSeconds);

  const hmacResults = await hmacOneTimePassword({
    ...options,
    hashAlgorithm: options.hashAlgorithm ?? "SHA-512",
    counter: BigInt(timeStepNum),
  });

  return { code: hmacResults.code };
}

/**
 * Calculate the number of time steps since t0.
 *
 * See https://www.rfc-editor.org/info/rfc6238/#section-4.2
 * @param unixTime The unix time (in seconds) to generate a code for.
 * @param timeStepSeconds The time step length in seconds.
 */
export function calculateTimeStepNumber(
  unixTime: number,
  timeStepSeconds: number,
) {
  const t0 = 0;
  const secondsFromT0 = unixTime - t0;
  return Math.floor(secondsFromT0 / timeStepSeconds);
}

function toUnixTime(date: Date): number {
  return Math.floor(date.getTime() / 1000); // Date getTime() is ms not seconds.
}
function fromUnixTime(unixTime: number): Date {
  return new Date(unixTime * 1000); // Convert seconds to ms
}
