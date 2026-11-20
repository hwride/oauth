/**
 * Parse an OAuth scope string into its individual scope values.
 */
export function parseScopeStr(scope: unknown) {
  return new Set(
    typeof scope === "string"
      ? scope.split(/\s+/).filter((scopeValue) => scopeValue.length > 0)
      : [],
  );
}

/**
 * Return whether an OAuth scope string has the given scope.
 */
export function hasScope(scope: unknown, expectedScope: string) {
  return parseScopeStr(scope).has(expectedScope);
}
