import {
  type CodeType,
  hmacOneTimePassword,
} from "./hmac-one-time-password.ts";

type TotpOptionsShared = {
  /** The key (secret) for the HMAC algorithm. */
  key: ArrayBuffer;
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

export type TotpOptionsValidator = TotpOptionsShared & {
  /** How many time steps to consider valid. It considers steps in the past valid, not in the future. Defaults to 1. */
  allowedTimeSteps?: number;
  /** Ability to set a custom store for storing used codes. This is needed to prevent code re-use. */
  customCodeStoreCreator?: CodeStoreCreator;
};

type CodeStoreCreator = (
  /**
   * You can use allowed time steps to perform clearing of entries that are no longer valid. You never need to store
   * more codes than the number of allowed time steps. But ensure you remove oldest codes first.
   */
  options: Required<Pick<TotpOptionsValidator, "allowedTimeSteps">>,
) => CodeStore;
type CodeStore = {
  /** Save a code that has been used. */
  save: (code: string) => Promise<void>;
  /** Return whether this code has been used before. */
  has: (code: string) => Promise<boolean>;
};

type TotpOptionsCode = TotpOptionsShared & {
  /** Optional time value to generate the code. Defaults to current time. */
  time?: Date;
};

const defaultTimeStepSeconds = 30;
const defaultAllowedTimeSteps = 1;

// TODO: Adjust HOTP to support different hash functions.

const createMemoryCodeStore: CodeStoreCreator = (options) => {
  const usedCodes = [];

  return {
    async save(code) {
      usedCodes.unshift(code);

      // Remove codes that could never be valid anymore anyway as we're passed that time.
      while (usedCodes.length > options.allowedTimeSteps) {
        usedCodes.shift();
      }
    },
    async has(code) {
      return usedCodes.includes(code);
    },
  };
};

export function createTimeBasedOneTimePasswordValidator(
  options: TotpOptionsValidator,
) {
  const optionsValidator = {
    ...options,
    timeStep: options.timeStep ?? defaultTimeStepSeconds,
    allowedTimeSteps: options.allowedTimeSteps ?? defaultAllowedTimeSteps,
    customCodeStoreCreator:
      options.customCodeStoreCreator ?? createMemoryCodeStore,
  };

  if (
    !Number.isInteger(optionsValidator.timeStep) ||
    optionsValidator.timeStep < 1
  ) {
    throw new Error("Invalid value for timeStep, must be > 0");
  }

  if (
    !Number.isInteger(optionsValidator.allowedTimeSteps) ||
    optionsValidator.allowedTimeSteps < 1
  ) {
    throw new Error("Invalid value for allowedTimeSteps, must be > 0");
  }

  const codeStoreCreator =
    options.customCodeStoreCreator ?? createMemoryCodeStore;
  const codeStore = codeStoreCreator({
    allowedTimeSteps: optionsValidator.allowedTimeSteps,
  });

  return {
    validate: async (
      expectedCode: string,
      {
        time,
      }: {
        /** Optional time value to generate the code. Defaults to current time. */
        time?: Date;
      } = {},
    ): Promise<{ isValid: boolean }> => {
      time ??= new Date();

      // Loop through all the allowed time steps starting from time, until we find a matching code or we fail to match.
      for (
        let timeStep = -optionsValidator.allowedTimeSteps + 1;
        timeStep <= 0;
        timeStep += 1
      ) {
        // Calculate time for this step.
        // Do calculation in Unix time to avoid any DST weirdness using Date.setSeconds
        const baseUnixTime = toUnixTime(time);
        const stepUnixTime =
          baseUnixTime + optionsValidator.timeStep * timeStep;
        const stepUnixTimeDate = fromUnixTime(stepUnixTime);

        // Get the code for this step.
        const { code } = await timeBasedOneTimePasswordCode({
          ...optionsValidator,
          time: stepUnixTimeDate,
        });

        // Check if we already used this code for this time step.
        // Make sure we save a combination of step time + code, in case two time values happen to generate the same code
        // we don't want to block use for the other time value.
        const stepTime = calculateTime(stepUnixTime, optionsValidator.timeStep);
        const codeStoreCode = `${stepTime}:${expectedCode}`;
        const codeStoreHasCode = await codeStore.has(codeStoreCode);

        // Didn't match or already used, try next step.
        if (code !== expectedCode || codeStoreHasCode) {
          continue;
        }

        // Check if code is valid.
        if (code === expectedCode) {
          await codeStore.save(codeStoreCode);
          return { isValid: true };
        }
      }

      return { isValid: false };
    },
  };
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
  const timeStep = options.timeStep ?? defaultTimeStepSeconds;
  if (!Number.isInteger(timeStep) || timeStep < 1) {
    throw new Error("Invalid value for timeStep, must be > 0");
  }

  const date = options.time ?? new Date();
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
function fromUnixTime(unixTime: number): Date {
  return new Date(unixTime * 1000); // Convert seconds to ms
}
