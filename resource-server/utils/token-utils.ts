/**
 * Check whether an OAuth scope string has the given scope.
 */
export function hasScope(
  scope: string | undefined,
  expectedScope: string,
): boolean {
  return scope?.split(/\s+/).includes(expectedScope) ?? false;
}

/**
 * Check whether an OpenID Connect `acr` claim matches the expected value.
 *
 * The `acr` claim is a single string value. This differs from the space-separated `acr_values` authorization request
 * parameter. https://openid.net/specs/openid-connect-core-1_0.html#Claims
 */
export function hasAcr(acr: string | undefined, expectedAcr: string): boolean {
  return acr === expectedAcr;
}

/** Check whether an authentication event is younger than the configured maximum age. */
export function hasRecentAuthTime(
  authTime: number | undefined,
  maxAgeSeconds: number,
): boolean {
  if (authTime === undefined || !Number.isFinite(authTime)) {
    return false;
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  return authTime <= nowSeconds && nowSeconds - authTime < maxAgeSeconds;
}
