/**
 * ARC Defender — Machine Learning Anomaly Detection Pipeline
 *
 * Implements Isolation Forest anomaly detection for HTTP client telemetry.
 */

import { config } from "./config.js";
import { db, MlResultRecord, RequestRecord } from "./database.js";
import { calculatePathEntropy } from "./stats.js";

interface ClientFeatureRow {
  ip: string;
  features: number[];
  featureDict: Record<string, number>;
}

function cFactor(n: number): number {
  if (n <= 1) return 0;
  if (n === 2) return 1;
  const H = Math.log(n - 1) + 0.5772156649; // Euler-Mascheroni constant
  return 2 * H - (2 * (n - 1)) / n;
}

interface ITreeNode {
  splitFeature?: number;
  splitValue?: number;
  left?: ITreeNode;
  right?: ITreeNode;
  size: number;
}

function buildITree(X: number[][], currentDepth: number, maxDepth: number): ITreeNode {
  const n = X.length;
  if (currentDepth >= maxDepth || n <= 1) {
    return { size: n };
  }

  const numFeatures = X[0].length;

  // Identify features with non-zero variance to avoid premature branch termination
  const candidates: { idx: number; min: number; max: number }[] = [];
  for (let f = 0; f < numFeatures; f++) {
    let minVal = Infinity;
    let maxVal = -Infinity;
    for (let i = 0; i < n; i++) {
      const v = X[i][f];
      if (v < minVal) minVal = v;
      if (v > maxVal) maxVal = v;
    }
    if (maxVal > minVal) {
      candidates.push({ idx: f, min: minVal, max: maxVal });
    }
  }

  if (candidates.length === 0) {
    return { size: n };
  }

  // Pick random valid feature from candidates
  const chosen = candidates[Math.floor(Math.random() * candidates.length)];
  const featureIdx = chosen.idx;
  const splitValue = chosen.min + Math.random() * (chosen.max - chosen.min);

  const leftX: number[][] = [];
  const rightX: number[][] = [];

  for (let i = 0; i < n; i++) {
    if (X[i][featureIdx] < splitValue) {
      leftX.push(X[i]);
    } else {
      rightX.push(X[i]);
    }
  }

  return {
    splitFeature: featureIdx,
    splitValue,
    size: n,
    left: buildITree(leftX, currentDepth + 1, maxDepth),
    right: buildITree(rightX, currentDepth + 1, maxDepth),
  };
}

function pathLength(x: number[], node: ITreeNode, currentDepth: number): number {
  if (node.left === undefined || node.right === undefined) {
    return currentDepth + (node.size > 1 ? cFactor(node.size) : 0);
  }

  const featureIdx = node.splitFeature!;
  if (x[featureIdx] < node.splitValue!) {
    return pathLength(x, node.left, currentDepth + 1);
  } else {
    return pathLength(x, node.right, currentDepth + 1);
  }
}

export function buildFeatureMatrix(hours = 24): {
  ips: string[];
  featureMatrix: number[][];
  featureNames: string[];
} | null {
  const cutoffIso = new Date(Date.now() - hours * 3600 * 1000).toISOString();
  const reqs = db.getRequestsSince(cutoffIso);
  if (reqs.length === 0) return null;

  const clientMap = new Map<string, RequestRecord[]>();
  for (const r of reqs) {
    const list = clientMap.get(r.ip) || [];
    list.push(r);
    clientMap.set(r.ip, list);
  }

  const featureNames = config.ML_FEATURES;
  const ips: string[] = [];
  const featureMatrix: number[][] = [];

  for (const [ip, ipReqs] of clientMap.entries()) {
    const count = ipReqs.length;
    if (count < config.ML_MIN_REQUESTS_PER_CLIENT) continue;

    let minTime = new Date(ipReqs[0].timestamp).getTime();
    let maxTime = new Date(ipReqs[0].timestamp).getTime();
    let errors = 0;
    let fourOhFours = 0;
    let totalTime = 0;
    let failedLogins = 0;
    let totalLogins = 0;
    const paths = new Set<string>();

    for (const r of ipReqs) {
      const t = new Date(r.timestamp).getTime();
      if (t < minTime) minTime = t;
      if (t > maxTime) maxTime = t;
      if (r.status_code >= 400) errors++;
      if (r.status_code === 404) fourOhFours++;
      totalTime += r.response_time_ms || 0;
      if (r.is_login_attempt === 1) {
        totalLogins++;
        if (r.login_success === 0) failedLogins++;
      }
      paths.add(r.path);
    }

    const timeSpanMin = Math.max(1.0, (maxTime - minTime) / (60 * 1000));
    const request_rate = count / timeSpanMin;
    const error_ratio = count > 0 ? errors / count : 0;
    const avg_response_time = count > 0 ? totalTime / count : 0;
    const failed_login_ratio = totalLogins > 0 ? failedLogins / totalLogins : 0;

    const entropyRes = calculatePathEntropy(ipReqs.map((r) => r.path));
    const path_entropy = entropyRes.normalizedEntropy;

    const row = [
      count,
      request_rate,
      errors,
      error_ratio,
      fourOhFours,
      paths.size,
      path_entropy,
      avg_response_time,
      failedLogins,
      failed_login_ratio,
    ];

    ips.push(ip);
    featureMatrix.push(row);
  }

  if (ips.length < config.ML_MIN_CLIENTS) {
    return null;
  }

  return { ips, featureMatrix, featureNames };
}

export function trainAndScore(hours = 24) {
  const data = buildFeatureMatrix(hours);
  if (!data) {
    return null;
  }

  const { ips, featureMatrix, featureNames } = data;
  const n = ips.length;
  const numFeatures = featureNames.length;

  // Calculate means and standard deviations
  const means: number[] = new Array(numFeatures).fill(0);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < numFeatures; j++) {
      means[j] += featureMatrix[i][j];
    }
  }
  for (let j = 0; j < numFeatures; j++) {
    means[j] /= n;
  }

  const stds: number[] = new Array(numFeatures).fill(0);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < numFeatures; j++) {
      stds[j] += Math.pow(featureMatrix[i][j] - means[j], 2);
    }
  }
  for (let j = 0; j < numFeatures; j++) {
    stds[j] = Math.sqrt(stds[j] / n) || 1e-6;
  }

  // Standardize X
  const scaledX: number[][] = [];
  for (let i = 0; i < n; i++) {
    const row: number[] = [];
    for (let j = 0; j < numFeatures; j++) {
      row.push((featureMatrix[i][j] - means[j]) / stds[j]);
    }
    scaledX.push(row);
  }

  // Train Isolation Forest with Subsampling (Liu et al. algorithm)
  const numTrees = config.ML_N_ESTIMATORS || 64;
  const subSampleSize = Math.min(64, n);
  const maxDepth = Math.ceil(Math.log2(Math.max(2, subSampleSize)));
  const forest: ITreeNode[] = [];

  for (let t = 0; t < numTrees; t++) {
    // Sample subSampleSize rows uniformly at random
    const sample: number[][] = [];
    for (let s = 0; s < subSampleSize; s++) {
      const idx = Math.floor(Math.random() * n);
      sample.push(scaledX[idx]);
    }
    forest.push(buildITree(sample, 0, maxDepth));
  }

  const cN = cFactor(subSampleSize) || 1;
  const rawScores: number[] = [];
  for (let i = 0; i < n; i++) {
    let totalPath = 0;
    for (const tree of forest) {
      totalPath += pathLength(scaledX[i], tree, 0);
    }
    const avgPath = totalPath / numTrees;
    const score = Math.pow(2, -avgPath / cN);
    rawScores.push(score);
  }

  const minScore = Math.min(...rawScores);
  const maxScore = Math.max(...rawScores);

  const normalizedScores = rawScores.map((s) => {
    if (maxScore === minScore) return 50.0;
    // Map between 0 and 100 with emphasis on high-isolation outliers
    return ((s - minScore) / (maxScore - minScore)) * 100.0;
  });

  const featureLabels: Record<string, string> = {
    request_count: "Request Volume",
    request_rate: "Request Rate",
    error_count: "5xx Errors",
    error_ratio: "Error Ratio",
    four_oh_four_count: "404 Scanning",
    unique_endpoints: "Endpoint Variety",
    path_entropy: "Path Entropy",
    avg_response_time: "Latency",
    failed_login_count: "Failed Logins",
    failed_login_ratio: "Failed Auth Ratio",
  };

  const results: any[] = [];
  let anomaly_count = 0;

  for (let i = 0; i < n; i++) {
    const ip = ips[i];
    const score = Math.round(normalizedScores[i] * 10) / 10;
    const is_anomaly = score >= 70 ? 1 : 0;

    const featureDict: Record<string, any> = {};
    for (let j = 0; j < numFeatures; j++) {
      featureDict[featureNames[j]] = Math.round(featureMatrix[i][j] * 100) / 100;
    }

    // Explainable Attribution: Compute standardized Z-score drivers
    const drivers: { feature: string; label: string; z_score: number; value: number }[] = [];
    for (let j = 0; j < numFeatures; j++) {
      const z = stds[j] > 0 ? (featureMatrix[i][j] - means[j]) / stds[j] : 0;
      if (z > 1.2) {
        drivers.push({
          feature: featureNames[j],
          label: featureLabels[featureNames[j]] || featureNames[j],
          z_score: Math.round(z * 10) / 10,
          value: Math.round(featureMatrix[i][j] * 100) / 100,
        });
      }
    }
    drivers.sort((a, b) => b.z_score - a.z_score);
    featureDict._top_drivers = drivers.slice(0, 3);

    db.insertMlResult({
      ip,
      anomaly_score: score,
      is_anomaly,
      features: JSON.stringify(featureDict),
    });

    if (is_anomaly) {
      anomaly_count++;
      const contributing = drivers.slice(0, 3).map((d) => `${d.label} (+${d.z_score}σ)`);

      let desc = `ML anomaly detected for ${ip} (anomaly score: ${score.toFixed(1)}).`;
      if (contributing.length > 0) {
        desc += ` Primary anomaly drivers: ${contributing.join(", ")}.`;
      }
      const severity = score > 80 ? "high" : "medium";

      db.insertAlert({
        alert_type: "ml_anomaly",
        severity,
        source: "ml",
        description: desc,
        ip,
        risk_score: score,
      });
    }

    results.push({
      ip,
      score,
      is_anomaly,
      features: featureDict,
      top_drivers: drivers.slice(0, 3),
    });
  }

  return {
    trained: true,
    client_count: n,
    anomaly_count,
    results,
  };
}

export function getMlResults(hours = 24) {
  const cutoffIso = new Date(Date.now() - hours * 3600 * 1000).toISOString();
  const list = db.getMlResultsSince(cutoffIso);
  list.sort((a, b) => b.timestamp.localeCompare(a.timestamp));

  // Deduplicate by IP to keep only the latest evaluation per client
  const seenIps = new Set<string>();
  const deduplicated: typeof list = [];
  for (const item of list) {
    if (!seenIps.has(item.ip)) {
      seenIps.add(item.ip);
      deduplicated.push(item);
    }
  }

  // Sort by anomaly_score descending (most anomalous clients first)
  deduplicated.sort((a, b) => (b.anomaly_score || 0) - (a.anomaly_score || 0));

  return deduplicated.map((r) => {
    let parsed: any = {};
    try {
      parsed = r.features ? JSON.parse(r.features) : {};
    } catch {
      parsed = {};
    }
    const top_drivers = parsed._top_drivers || [];
    const cleanFeatures = { ...parsed };
    delete cleanFeatures._top_drivers;

    return {
      id: r.id,
      ip: r.ip,
      timestamp: r.timestamp,
      anomaly_score: r.anomaly_score,
      is_anomaly: r.is_anomaly,
      features: cleanFeatures,
      top_drivers,
    };
  });
}

export function getMlStatus() {
  const all = db.getAllMlResults();
  if (all.length === 0) {
    return {
      has_model: false,
      last_run: null,
      client_count: 0,
      anomaly_count: 0,
    };
  }

  // Find max timestamp
  let latestTs = all[0].timestamp;
  for (const item of all) {
    if (item.timestamp > latestTs) latestTs = item.timestamp;
  }

  const latestBatch = all.filter((m) => m.timestamp === latestTs);
  const ips = new Set(latestBatch.map((m) => m.ip));
  let anomalies = 0;
  for (const m of latestBatch) {
    if (m.is_anomaly) anomalies++;
  }

  return {
    has_model: true,
    last_run: latestTs,
    client_count: ips.size,
    anomaly_count: anomalies,
  };
}
