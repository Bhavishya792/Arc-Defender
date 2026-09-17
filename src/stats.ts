/**
 * ARC Defender — Statistical and Information-Theoretic Utilities
 *
 * Implements Shannon Entropy for endpoint fuzzing/traversal detection
 * and basic statistical process control functions (Mean, StdDev, Z-Score).
 */

/**
 * Calculates Shannon Entropy H(X) and normalized entropy for a sequence of paths.
 *
 * H(X) = - sum(p_i * log2(p_i))
 * Normalized H = H(X) / log2(k) where k is the number of distinct outcomes (0.0 to 1.0).
 * High normalized entropy with high distinct paths indicates automated fuzzing/scanning.
 */
export function calculatePathEntropy(paths: string[]): {
  entropy: number;
  normalizedEntropy: number;
  distinctCount: number;
  totalCount: number;
} {
  const totalCount = paths.length;
  if (totalCount === 0) {
    return { entropy: 0, normalizedEntropy: 0, distinctCount: 0, totalCount: 0 };
  }

  const freqMap = new Map<string, number>();
  for (const p of paths) {
    freqMap.set(p, (freqMap.get(p) || 0) + 1);
  }

  const distinctCount = freqMap.size;
  if (distinctCount <= 1) {
    return { entropy: 0, normalizedEntropy: 0, distinctCount, totalCount };
  }

  let entropy = 0.0;
  for (const count of freqMap.values()) {
    const p = count / totalCount;
    entropy -= p * Math.log2(p);
  }

  // Maximum theoretical entropy for k discrete symbols is log2(k)
  const maxEntropy = Math.log2(distinctCount);
  const normalizedEntropy = maxEntropy > 0 ? entropy / maxEntropy : 0.0;

  return {
    entropy: Math.round(entropy * 1000) / 1000,
    normalizedEntropy: Math.round(normalizedEntropy * 1000) / 1000,
    distinctCount,
    totalCount,
  };
}

/**
 * Calculates arithmetic mean and standard deviation.
 */
export function calculateMeanAndStd(values: number[]): { mean: number; std: number } {
  const n = values.length;
  if (n === 0) return { mean: 0, std: 0 };
  if (n === 1) return { mean: values[0], std: 0 };

  const mean = values.reduce((sum, v) => sum + v, 0) / n;
  const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / n;
  const std = Math.sqrt(variance);

  return { mean, std };
}

/**
 * Standardized Z-Score: (x - mean) / std.
 */
export function calculateZScore(val: number, mean: number, std: number): number {
  if (std === 0 || isNaN(std)) return 0;
  return (val - mean) / std;
}
