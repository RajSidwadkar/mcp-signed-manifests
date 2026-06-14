/**
 * Canonical JSON serialization.
 *
 * Signing only works reliably if the same logical object always produces
 * the exact same byte string. Plain JSON.stringify does NOT guarantee key
 * order, so two semantically-identical objects could produce different
 * signatures (or worse, an attacker could reorder keys to dodge a naive
 * comparison). This function recursively sorts object keys before
 * serializing, so the output is deterministic regardless of how the object
 * was constructed.
 */
export function canonicalJSON(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }

  if (value !== null && typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }

  return value;
}
