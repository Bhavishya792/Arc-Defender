/**
 * ARC Defender — Centralized Configuration
 */

export const config = {
  PORT: parseInt(process.env.PORT || "3000", 10),
  HOST: process.env.HOST || "0.0.0.0",

  // Security Detection Thresholds
  BRUTE_FORCE_THRESHOLD: 5,
  BRUTE_FORCE_WINDOW_SECONDS: 60,

  HIGH_RATE_THRESHOLD: 100,
  HIGH_RATE_WINDOW_SECONDS: 60,

  SCAN_404_THRESHOLD: 15,
  SCAN_404_WINDOW_SECONDS: 120,

  ENTROPY_SCAN_THRESHOLD: 0.85,
  ENTROPY_SCAN_MIN_PATHS: 6,
  ENTROPY_WINDOW_SECONDS: 120,

  ERROR_SPIKE_THRESHOLD: 20,
  ERROR_SPIKE_WINDOW_SECONDS: 60,

  // Severity mapping
  SEVERITY_BRUTE_FORCE: "high",
  SEVERITY_HIGH_RATE: "medium",
  SEVERITY_SCAN: "medium",
  SEVERITY_ENTROPY: "medium",
  SEVERITY_ERROR_SPIKE: "high",

  // Risk Score Weights
  RISK_WEIGHT_BRUTE_FORCE: 0.25,
  RISK_WEIGHT_HIGH_RATE: 0.20,
  RISK_WEIGHT_SCAN: 0.15,
  RISK_WEIGHT_ENTROPY: 0.15,
  RISK_WEIGHT_ERROR: 0.10,
  RISK_WEIGHT_ML_ANOMALY: 0.15,

  // Machine Learning
  ML_MIN_CLIENTS: 5,
  ML_MIN_REQUESTS_PER_CLIENT: 3,
  ML_CONTAMINATION: 0.05,
  ML_N_ESTIMATORS: 100,
  ML_RANDOM_STATE: 42,
  ML_FEATURES: [
    "request_count",
    "request_rate",
    "error_count",
    "error_ratio",
    "four_oh_four_count",
    "unique_endpoints",
    "path_entropy",
    "avg_response_time",
    "failed_login_count",
    "failed_login_ratio",
  ],

  DEFAULT_TIME_RANGE_HOURS: 24,
};
