/**
 * ARC Defender — Deterministic Detection Module
 */

import { config } from "./config.js";
import { db, AlertRecord } from "./database.js";
import { calculatePathEntropy, calculateMeanAndStd, calculateZScore } from "./stats.js";

function isDuplicateAlert(alert_type: string, ip: string | null, window_seconds: number): boolean {
  const thresholdIso = new Date(Date.now() - window_seconds * 1000).toISOString();
  const alerts = db.getAllAlerts();
  return alerts.some((a) => {
    if (a.alert_type !== alert_type) return false;
    if (a.timestamp <= thresholdIso) return false;
    if (ip) {
      return a.ip === ip;
    }
    return true;
  });
}

export function detectBruteForce(): AlertRecord[] {
  const newAlerts: AlertRecord[] = [];
  const thresholdIso = new Date(Date.now() - config.BRUTE_FORCE_WINDOW_SECONDS * 1000).toISOString();
  const reqs = db.getRequestsSince(thresholdIso);

  const ipCounts = new Map<string, number>();
  for (const r of reqs) {
    if (r.is_login_attempt === 1 && r.login_success === 0) {
      ipCounts.set(r.ip, (ipCounts.get(r.ip) || 0) + 1);
    }
  }

  for (const [ip, failed_attempts] of ipCounts.entries()) {
    if (failed_attempts > config.BRUTE_FORCE_THRESHOLD) {
      const alert_type = "brute_force";
      if (!isDuplicateAlert(alert_type, ip, config.BRUTE_FORCE_WINDOW_SECONDS)) {
        const description = `${ip} generated ${failed_attempts} failed login attempts within ${config.BRUTE_FORCE_WINDOW_SECONDS} seconds.`;
        const risk_info = calculateRiskScore(ip);
        const alert = db.insertAlert({
          alert_type,
          severity: config.SEVERITY_BRUTE_FORCE,
          ip,
          description,
          source: "rule",
          stats: JSON.stringify({
            failed_attempts,
            window_seconds: config.BRUTE_FORCE_WINDOW_SECONDS,
          }),
          risk_score: risk_info.score,
        });
        newAlerts.push(alert);
      }
    }
  }

  return newAlerts;
}

export function detectHighRate(): AlertRecord[] {
  const newAlerts: AlertRecord[] = [];
  const thresholdIso = new Date(Date.now() - config.HIGH_RATE_WINDOW_SECONDS * 1000).toISOString();
  const reqs = db.getRequestsSince(thresholdIso);

  const ipCounts = new Map<string, number>();
  for (const r of reqs) {
    ipCounts.set(r.ip, (ipCounts.get(r.ip) || 0) + 1);
  }

  // Calculate moving statistical baseline across all observed clients
  const counts = Array.from(ipCounts.values());
  const { mean, std } = calculateMeanAndStd(counts);
  const threeSigmaLimit = Math.round(mean + 2.5 * std);
  const effectiveThreshold = Math.max(config.HIGH_RATE_THRESHOLD, Math.min(threeSigmaLimit, config.HIGH_RATE_THRESHOLD * 2));

  for (const [ip, req_count] of ipCounts.entries()) {
    if (req_count > effectiveThreshold || (counts.length >= 4 && req_count > config.HIGH_RATE_THRESHOLD * 0.7 && req_count > mean + 3.0 * std)) {
      const alert_type = "high_rate";
      if (!isDuplicateAlert(alert_type, ip, config.HIGH_RATE_WINDOW_SECONDS)) {
        const zScore = calculateZScore(req_count, mean, std);
        const description = `${ip} generated ${req_count} requests in ${config.HIGH_RATE_WINDOW_SECONDS}s (Statistical anomaly: Z = +${zScore.toFixed(1)}σ vs cluster baseline μ=${mean.toFixed(1)} ± ${std.toFixed(1)}).`;
        const risk_info = calculateRiskScore(ip);
        const alert = db.insertAlert({
          alert_type,
          severity: config.SEVERITY_HIGH_RATE,
          ip,
          description,
          source: "rule",
          stats: JSON.stringify({
            request_count: req_count,
            window_seconds: config.HIGH_RATE_WINDOW_SECONDS,
            z_score: Math.round(zScore * 10) / 10,
            cluster_mean: Math.round(mean * 10) / 10,
            cluster_std: Math.round(std * 10) / 10,
          }),
          risk_score: risk_info.score,
        });
        newAlerts.push(alert);
      }
    }
  }

  return newAlerts;
}

export function detectEntropyScanning(): AlertRecord[] {
  const newAlerts: AlertRecord[] = [];
  const thresholdIso = new Date(Date.now() - config.ENTROPY_WINDOW_SECONDS * 1000).toISOString();
  const reqs = db.getRequestsSince(thresholdIso);

  const ipPaths = new Map<string, string[]>();
  for (const r of reqs) {
    const list = ipPaths.get(r.ip) || [];
    list.push(r.path);
    ipPaths.set(r.ip, list);
  }

  for (const [ip, paths] of ipPaths.entries()) {
    if (paths.length < config.ENTROPY_SCAN_MIN_PATHS) continue;

    const { entropy, normalizedEntropy, distinctCount, totalCount } = calculatePathEntropy(paths);

    // If normalized entropy is high across 6+ unique paths, automated fuzzing is occurring
    if (distinctCount >= config.ENTROPY_SCAN_MIN_PATHS && normalizedEntropy >= config.ENTROPY_SCAN_THRESHOLD) {
      const alert_type = "entropy_scanning";
      if (!isDuplicateAlert(alert_type, ip, config.ENTROPY_WINDOW_SECONDS)) {
        const description = `${ip} exhibited high Shannon path entropy H=${entropy.toFixed(2)} bits (${Math.round(normalizedEntropy * 100)}% of max diversity over ${distinctCount} endpoints), indicating automated directory fuzzing.`;
        const risk_info = calculateRiskScore(ip);
        const alert = db.insertAlert({
          alert_type,
          severity: config.SEVERITY_ENTROPY,
          ip,
          description,
          source: "rule",
          stats: JSON.stringify({
            shannon_entropy: entropy,
            normalized_entropy: normalizedEntropy,
            distinct_paths: distinctCount,
            total_requests: totalCount,
            window_seconds: config.ENTROPY_WINDOW_SECONDS,
          }),
          risk_score: risk_info.score,
        });
        newAlerts.push(alert);
      }
    }
  }

  return newAlerts;
}

export function detectEndpointScanning(): AlertRecord[] {
  const newAlerts: AlertRecord[] = [];
  const thresholdIso = new Date(Date.now() - config.SCAN_404_WINDOW_SECONDS * 1000).toISOString();
  const reqs = db.getRequestsSince(thresholdIso);

  const ipCounts = new Map<string, number>();
  for (const r of reqs) {
    if (r.status_code === 404) {
      ipCounts.set(r.ip, (ipCounts.get(r.ip) || 0) + 1);
    }
  }

  for (const [ip, not_found_count] of ipCounts.entries()) {
    if (not_found_count > config.SCAN_404_THRESHOLD) {
      const alert_type = "endpoint_scanning";
      if (!isDuplicateAlert(alert_type, ip, config.SCAN_404_WINDOW_SECONDS)) {
        const description = `${ip} received ${not_found_count} 404 Not Found responses within ${config.SCAN_404_WINDOW_SECONDS} seconds.`;
        const risk_info = calculateRiskScore(ip);
        const alert = db.insertAlert({
          alert_type,
          severity: config.SEVERITY_SCAN,
          ip,
          description,
          source: "rule",
          stats: JSON.stringify({
            "404_count": not_found_count,
            window_seconds: config.SCAN_404_WINDOW_SECONDS,
          }),
          risk_score: risk_info.score,
        });
        newAlerts.push(alert);
      }
    }
  }

  return newAlerts;
}

export function detectErrorSpike(): AlertRecord[] {
  const newAlerts: AlertRecord[] = [];
  const thresholdIso = new Date(Date.now() - config.ERROR_SPIKE_WINDOW_SECONDS * 1000).toISOString();
  const reqs = db.getRequestsSince(thresholdIso);

  let error_count = 0;
  for (const r of reqs) {
    if (r.status_code >= 500) {
      error_count++;
    }
  }

  if (error_count > config.ERROR_SPIKE_THRESHOLD) {
    const alert_type = "error_spike";
    if (!isDuplicateAlert(alert_type, null, config.ERROR_SPIKE_WINDOW_SECONDS)) {
      const description = `System-wide error spike: ${error_count} 5xx errors detected within ${config.ERROR_SPIKE_WINDOW_SECONDS} seconds.`;
      const alert = db.insertAlert({
        alert_type,
        severity: config.SEVERITY_ERROR_SPIKE,
        ip: null,
        description,
        source: "rule",
        stats: JSON.stringify({
          error_count,
          window_seconds: config.ERROR_SPIKE_WINDOW_SECONDS,
        }),
        risk_score: 0.0,
      });
      newAlerts.push(alert);
    }
  }

  return newAlerts;
}

export function calculateRiskScore(ip: string): { score: number; reasons: string[] } {
  let score = 0.0;
  const reasons: string[] = [];
  const thresholdIso = new Date(Date.now() - 3600 * 1000).toISOString(); // 1 hour window

  const recent = db.getRequestsSince(thresholdIso).filter((r) => r.ip === ip);

  // 1. Brute Force Signals
  let failed_logins = 0;
  let total_logins = 0;
  let total_requests = 0;
  let not_found_count = 0;
  let error_count = 0;

  for (const r of recent) {
    total_requests++;
    if (r.is_login_attempt === 1) {
      total_logins++;
      if (r.login_success === 0) failed_logins++;
    }
    if (r.status_code === 404) not_found_count++;
    if (r.status_code >= 500) error_count++;
  }

  if (total_logins > 0) {
    const failed_ratio = failed_logins / total_logins;
    if (failed_ratio > 0.5 && failed_logins > 5) {
      const points = failed_ratio * config.RISK_WEIGHT_BRUTE_FORCE * 100;
      score += points;
      reasons.push(`High failed login ratio (${failed_ratio.toFixed(2)})`);
    }
  }

  // 2. High Request Rate Signals
  const highRateLimit = config.HIGH_RATE_THRESHOLD * (3600 / config.HIGH_RATE_WINDOW_SECONDS) * 0.1;
  if (total_requests > highRateLimit) {
    const points = (total_requests / 1000) * config.RISK_WEIGHT_HIGH_RATE * 100;
    score += points;
    reasons.push(`High request volume (${total_requests} in 1h)`);
  }

  // 3. Scanning Signals (404s)
  if (not_found_count > 10) {
    const points = (not_found_count / 10) * config.RISK_WEIGHT_SCAN * 10;
    score += points;
    reasons.push(`Frequent 404s (${not_found_count} in 1h)`);
  }

  // 4. Shannon Path Entropy Analysis (Fuzzing/Discovery)
  if (recent.length >= 6) {
    const { normalizedEntropy, distinctCount, entropy } = calculatePathEntropy(recent.map((r) => r.path));
    if (distinctCount >= config.ENTROPY_SCAN_MIN_PATHS && normalizedEntropy >= config.ENTROPY_SCAN_THRESHOLD) {
      const points = normalizedEntropy * config.RISK_WEIGHT_ENTROPY * 100;
      score += points;
      reasons.push(`High Shannon path entropy (H=${entropy.toFixed(2)}, ${Math.round(normalizedEntropy * 100)}% randomness across ${distinctCount} routes)`);
    }
  }

  // 5. Error Signals
  if (error_count > 5) {
    const points = (error_count / 5) * config.RISK_WEIGHT_ERROR * 10;
    score += points;
    reasons.push(`Causing 5xx errors (${error_count} in 1h)`);
  }

  // 6. ML Anomaly
  const mlResults = db.getMlResultsSince(thresholdIso).filter((m) => m.ip === ip);
  if (mlResults.length > 0) {
    const lastMl = mlResults[mlResults.length - 1];
    const anomaly_score = lastMl.anomaly_score;
    const points = anomaly_score * config.RISK_WEIGHT_ML_ANOMALY;
    score += points;
    reasons.push(`ML Anomaly score: ${anomaly_score.toFixed(2)}`);
  }

  // 7. Multi-Stage Attack Kill-Chain Bonus
  const killChain = classifyKillChainStage(ip);
  if (killChain.stagesIdentified.length >= 2) {
    score += 15.0;
    reasons.push(`Multi-Stage Progression: ${killChain.stagesIdentified.join(" → ")}`);
  }

  const final_score = Math.min(score, 100.0);
  return { score: Math.round(final_score * 10) / 10, reasons };
}

/**
 * Heuristic Cyber Kill-Chain Stage Classifier
 * Correlates discrete signals into recognizable attack progression phases.
 */
export function classifyKillChainStage(ip: string): {
  stage: string;
  stagesIdentified: string[];
  chainSummary: string;
} {
  const thresholdIso = new Date(Date.now() - 3600 * 1000).toISOString();
  const recentReqs = db.getRequestsSince(thresholdIso).filter((r) => r.ip === ip);
  const recentAlerts = db.getAlertsSince(thresholdIso).filter((a) => a.ip === ip);

  const alertTypes = new Set(recentAlerts.map((a) => a.alert_type));

  let hasRecon = alertTypes.has("endpoint_scanning") || alertTypes.has("entropy_scanning");
  let hasCredential = alertTypes.has("brute_force");
  let hasExploit = alertTypes.has("high_rate");

  let notFoundCount = 0;
  let failedLogins = 0;
  let serverErrors = 0;

  for (const r of recentReqs) {
    if (r.status_code === 404) notFoundCount++;
    if (r.is_login_attempt === 1 && r.login_success === 0) failedLogins++;
    if (r.status_code >= 500) serverErrors++;
  }

  if (notFoundCount >= 8) hasRecon = true;
  if (failedLogins >= 3) hasCredential = true;
  if (recentReqs.length >= 70 || serverErrors >= 4) hasExploit = true;

  const stages: string[] = [];
  if (hasRecon) stages.push("Reconnaissance");
  if (hasCredential) stages.push("Credential Probing");
  if (hasExploit) stages.push("Exploitation / DoS");

  let stage = "Benign";
  let chainSummary = "No hostile multi-stage progression detected";

  if (stages.length >= 3) {
    stage = "Multi-Stage Kill Chain (Full Progression)";
    chainSummary = "Observed reconnaissance, credential attacks, and traffic exhaustion in sequence.";
  } else if (stages.length === 2) {
    stage = `Multi-Stage Intrusion (${stages.join(" + ")})`;
    chainSummary = `Correlated hostile signals across ${stages.join(" and ")}.`;
  } else if (stages.length === 1) {
    stage = stages[0];
    chainSummary = `Isolated ${stages[0]} activity observed.`;
  }

  return { stage, stagesIdentified: stages, chainSummary };
}

export function runAllDetections(): AlertRecord[] {
  const all: AlertRecord[] = [];
  all.push(...detectBruteForce());
  all.push(...detectHighRate());
  all.push(...detectEndpointScanning());
  all.push(...detectEntropyScanning());
  all.push(...detectErrorSpike());
  return all;
}

export function getAlerts(
  hours = 24,
  limit = 50,
  severity?: string,
  status?: "active" | "acknowledged" | "all"
): AlertRecord[] {
  const thresholdIso = new Date(Date.now() - hours * 3600 * 1000).toISOString();
  let list = db.getAlertsSince(thresholdIso);

  if (severity && severity !== "all") {
    list = list.filter((a) => a.severity.toLowerCase() === severity.toLowerCase());
  }

  if (status === "active") {
    list = list.filter((a) => !a.acknowledged);
  } else if (status === "acknowledged") {
    list = list.filter((a) => !!a.acknowledged);
  }

  list.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  return list.slice(0, limit);
}

export function getThreatStatus(hours = 24) {
  const thresholdIso = new Date(Date.now() - hours * 3600 * 1000).toISOString();
  const alerts = db.getAlertsSince(thresholdIso);
  const activeAlerts = alerts.filter((a) => !a.acknowledged);
  const criticalCount = activeAlerts.filter((a) => a.severity === "high" || a.severity === "critical").length;
  const mediumCount = activeAlerts.filter((a) => a.severity === "medium").length;

  const suspicious = getSuspiciousClients(hours);
  const highRiskClients = suspicious.filter((c) => c.risk_score >= 60);

  let threat_level: "CRITICAL" | "ELEVATED" | "NORMAL" = "NORMAL";
  let status_message = "Normal system traffic. No urgent active threats detected.";

  if (criticalCount > 0 || highRiskClients.length > 0) {
    threat_level = "CRITICAL";
    status_message = `${criticalCount} high-severity active threat(s) detected. Immediate investigation recommended.`;
  } else if (mediumCount > 0 || activeAlerts.length > 0) {
    threat_level = "ELEVATED";
    status_message = `Elevated activity: ${activeAlerts.length} active security alert(s) under observation.`;
  }

  const latest_threat = activeAlerts.length > 0
    ? [...activeAlerts].sort((a, b) => b.timestamp.localeCompare(a.timestamp))[0]
    : null;

  return {
    threat_level,
    status_message,
    active_alert_count: activeAlerts.length,
    total_alert_count: alerts.length,
    critical_count: criticalCount,
    medium_count: mediumCount,
    high_risk_clients_count: highRiskClients.length,
    latest_threat,
  };
}

export function getSuspiciousClients(hours = 24) {
  const thresholdIso = new Date(Date.now() - hours * 3600 * 1000).toISOString();
  const alerts = db.getAlertsSince(thresholdIso);

  const ipMap = new Map<string, { count: number; alert_types: Set<string> }>();
  for (const a of alerts) {
    if (!a.ip) continue;
    const item = ipMap.get(a.ip) || { count: 0, alert_types: new Set() };
    item.count++;
    item.alert_types.add(a.alert_type);
    ipMap.set(a.ip, item);
  }

  const list = Array.from(ipMap.entries()).map(([ip, data]) => {
    const risk = calculateRiskScore(ip);
    const kill_chain = classifyKillChainStage(ip);
    return {
      ip,
      alert_count: data.count,
      alert_types: Array.from(data.alert_types).join(","),
      risk_score: risk.score,
      risk_reasons: risk.reasons,
      kill_chain,
    };
  });

  list.sort((a, b) => b.alert_count - a.alert_count);
  return list;
}
