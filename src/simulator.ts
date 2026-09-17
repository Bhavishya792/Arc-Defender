/**
 * ARC Defender — Traffic Simulator & Initial Seeder
 *
 * Seeds synthetic yet realistic HTTP traffic for monitoring, analytics,
 * security detection, and ML anomaly evaluation.
 */

import { db } from "./database.js";
import { runAllDetections } from "./detection.js";
import { trainAndScore } from "./mlEngine.js";

const NORMAL_IPS = Array.from({ length: 20 }, (_, i) => `10.0.1.${i + 1}`);
const ATTACKER_IPS = Array.from({ length: 5 }, (_, i) => `10.0.99.${i + 1}`);

const NORMAL_ENDPOINTS = [
  "/",
  "/api/users",
  "/api/users/1",
  "/api/users/2",
  "/api/users/3",
  "/api/products",
  "/api/orders",
  "/api/health",
];

const SCAN_ENDPOINTS = [
  "/admin",
  "/wp-admin",
  "/phpmyadmin",
  "/.env",
  "/config.json",
  "/api/secret",
  "/api/admin/users",
  "/backup",
  "/debug",
  "/api/v2/internal",
  "/.git/config",
  "/server-status",
  "/api/keys",
  "/console",
  "/api/token",
  "/swagger.json",
  "/robots.txt",
  "/sitemap.xml",
];

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/17.0",
  "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
  "python-requests/2.31.0",
  "curl/8.4.0",
  "PostmanRuntime/7.36.0",
];

export function seedInitialData() {
  if (db.getAllRequests().length > 0) return;

  const now = Date.now();

  // 1. Normal traffic spread over past 24 hours
  for (let i = 0; i < 450; i++) {
    const ageMinutes = Math.floor(Math.random() * (24 * 60));
    const timestamp = new Date(now - ageMinutes * 60 * 1000).toISOString();
    const ip = NORMAL_IPS[Math.floor(Math.random() * NORMAL_IPS.length)];
    const path = NORMAL_ENDPOINTS[Math.floor(Math.random() * NORMAL_ENDPOINTS.length)];
    const method = path === "/api/orders" && Math.random() < 0.2 ? "POST" : "GET";
    const status_code = 200;
    const response_time_ms = Math.round(5 + Math.random() * 45);
    const user_agent = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

    db.insertRequest({
      timestamp,
      ip,
      method,
      path,
      status_code,
      response_time_ms,
      user_agent,
      request_size: method === "POST" ? 128 : 0,
      response_size: 512,
    });
  }

  // 2. Normal login attempts
  for (let i = 0; i < 40; i++) {
    const ageMinutes = Math.floor(Math.random() * (24 * 60));
    const timestamp = new Date(now - ageMinutes * 60 * 1000).toISOString();
    const ip = NORMAL_IPS[Math.floor(Math.random() * NORMAL_IPS.length)];
    const success = Math.random() > 0.1;

    db.insertRequest({
      timestamp,
      ip,
      method: "POST",
      path: "/api/login",
      status_code: success ? 200 : 401,
      response_time_ms: Math.round(15 + Math.random() * 30),
      user_agent: USER_AGENTS[0],
      is_login_attempt: 1,
      login_success: success ? 1 : 0,
    });
  }

  // 3. Attacker 1: Brute Force on /api/login (past 30 seconds)
  const bruteIp = ATTACKER_IPS[0];
  for (let i = 0; i < 12; i++) {
    const ageSeconds = Math.floor(Math.random() * 45);
    const timestamp = new Date(now - ageSeconds * 1000).toISOString();
    db.insertRequest({
      timestamp,
      ip: bruteIp,
      method: "POST",
      path: "/api/login",
      status_code: 401,
      response_time_ms: Math.round(12 + Math.random() * 20),
      user_agent: "python-requests/2.31.0",
      is_login_attempt: 1,
      login_success: 0,
    });
  }

  // 4. Attacker 2: High Rate (past 40 seconds)
  const highRateIp = ATTACKER_IPS[1];
  for (let i = 0; i < 115; i++) {
    const ageSeconds = Math.floor(Math.random() * 50);
    const timestamp = new Date(now - ageSeconds * 1000).toISOString();
    db.insertRequest({
      timestamp,
      ip: highRateIp,
      method: "GET",
      path: "/api/products",
      status_code: 200,
      response_time_ms: Math.round(3 + Math.random() * 15),
      user_agent: "curl/8.4.0",
    });
  }

  // 5. Attacker 3: Endpoint Scanning (past 60 seconds)
  const scanIp = ATTACKER_IPS[2];
  for (let i = 0; i < SCAN_ENDPOINTS.length; i++) {
    const ageSeconds = Math.floor(Math.random() * 90);
    const timestamp = new Date(now - ageSeconds * 1000).toISOString();
    db.insertRequest({
      timestamp,
      ip: scanIp,
      method: "GET",
      path: SCAN_ENDPOINTS[i],
      status_code: 404,
      response_time_ms: Math.round(8 + Math.random() * 25),
      user_agent: "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
    });
  }

  // 6. Error Spike (past 30 seconds)
  for (let i = 0; i < 25; i++) {
    const ageSeconds = Math.floor(Math.random() * 50);
    const timestamp = new Date(now - ageSeconds * 1000).toISOString();
    const ip = `10.0.88.${(i % 10) + 1}`;
    db.insertRequest({
      timestamp,
      ip,
      method: "GET",
      path: "/api/error",
      status_code: 500,
      response_time_ms: Math.round(50 + Math.random() * 100),
      user_agent: USER_AGENTS[1],
    });
  }

  // 7. Run initial detection rules and ML training
  runAllDetections();
  trainAndScore(24);
}

export function simulateAttack(type: string): { type: string; message: string; requestsAdded: number; newAlerts: any[] } {
  const now = Date.now();
  let requestsAdded = 0;
  let message = "";

  if (type === "brute_force") {
    const ip = `198.51.100.${Math.floor(Math.random() * 50) + 10}`;
    for (let i = 0; i < 15; i++) {
      const ageSeconds = Math.floor(Math.random() * 25);
      db.insertRequest({
        timestamp: new Date(now - ageSeconds * 1000).toISOString(),
        ip,
        method: "POST",
        path: "/api/login",
        status_code: 401,
        response_time_ms: Math.round(15 + Math.random() * 30),
        user_agent: "Hydra/9.5 (BruteForce)",
        is_login_attempt: 1,
        login_success: 0,
      });
      requestsAdded++;
    }
    message = `Simulated credential brute-force attack from ${ip} (15 failed logins).`;
  } else if (type === "scanner") {
    const ip = `203.0.113.${Math.floor(Math.random() * 50) + 10}`;
    const scanPaths = [
      "/.env", "/admin", "/wp-login.php", "/config.json", "/.git/config",
      "/api/v1/debug", "/backup.sql", "/phpmyadmin", "/actuator/health", "/swagger.json",
      "/server-status", "/console"
    ];
    for (const p of scanPaths) {
      const ageSeconds = Math.floor(Math.random() * 30);
      db.insertRequest({
        timestamp: new Date(now - ageSeconds * 1000).toISOString(),
        ip,
        method: "GET",
        path: p,
        status_code: 404,
        response_time_ms: Math.round(10 + Math.random() * 20),
        user_agent: "Nikto/2.1.6 Vulnerability Scanner",
      });
      requestsAdded++;
    }
    message = `Simulated automated vulnerability path scan from ${ip} (${scanPaths.length} probe paths).`;
  } else if (type === "high_rate") {
    const ip = `192.0.2.${Math.floor(Math.random() * 50) + 10}`;
    for (let i = 0; i < 125; i++) {
      const ageSeconds = Math.floor(Math.random() * 35);
      db.insertRequest({
        timestamp: new Date(now - ageSeconds * 1000).toISOString(),
        ip,
        method: "GET",
        path: "/api/products",
        status_code: 200,
        response_time_ms: Math.round(4 + Math.random() * 12),
        user_agent: "ApacheBench/2.3",
      });
      requestsAdded++;
    }
    message = `Simulated Layer-7 DoS high-rate flood from ${ip} (125 requests in 35s).`;
  } else if (type === "error_spike") {
    for (let i = 0; i < 30; i++) {
      const ageSeconds = Math.floor(Math.random() * 30);
      const ip = `10.0.99.${(i % 8) + 1}`;
      db.insertRequest({
        timestamp: new Date(now - ageSeconds * 1000).toISOString(),
        ip,
        method: "POST",
        path: "/api/checkout",
        status_code: 500,
        response_time_ms: Math.round(100 + Math.random() * 150),
        user_agent: USER_AGENTS[0],
      });
      requestsAdded++;
    }
    message = `Simulated backend cascade failure & 500 error spike (30 error responses).`;
  } else if (type === "multi_stage") {
    const ip = `198.51.100.${Math.floor(Math.random() * 80) + 20}`;
    // Phase 1: Reconnaissance (8 diverse paths -> triggers high Shannon entropy + 404 scans)
    const reconPaths = ["/.env", "/wp-login.php", "/.git/config", "/api/v1/debug", "/admin", "/phpmyadmin", "/backup.zip", "/actuator"];
    for (const p of reconPaths) {
      const ageSeconds = Math.floor(Math.random() * 35) + 25;
      db.insertRequest({
        timestamp: new Date(now - ageSeconds * 1000).toISOString(),
        ip,
        method: "GET",
        path: p,
        status_code: 404,
        response_time_ms: 18,
        user_agent: "FuzzBot/2.4 (Recon)",
      });
      requestsAdded++;
    }
    // Phase 2: Credential Probing (7 failed logins)
    for (let i = 0; i < 7; i++) {
      const ageSeconds = Math.floor(Math.random() * 20) + 12;
      db.insertRequest({
        timestamp: new Date(now - ageSeconds * 1000).toISOString(),
        ip,
        method: "POST",
        path: "/api/login",
        status_code: 401,
        response_time_ms: 35,
        user_agent: "Hydra/9.5 (BruteForce)",
        is_login_attempt: 1,
        login_success: 0,
      });
      requestsAdded++;
    }
    // Phase 3: Exploitation / Rate Burst (110 requests in short window)
    for (let i = 0; i < 110; i++) {
      const ageSeconds = Math.floor(Math.random() * 12);
      db.insertRequest({
        timestamp: new Date(now - ageSeconds * 1000).toISOString(),
        ip,
        method: "GET",
        path: "/api/products",
        status_code: 200,
        response_time_ms: 12,
        user_agent: "ApacheBench/2.3",
      });
      requestsAdded++;
    }
    message = `Simulated multi-stage Cyber Kill Chain attack from ${ip}: Recon (8 probes) → Credential Access (7 failed logins) → DoS Burst (110 reqs).`;
  } else {
    // Normal traffic burst
    for (let i = 0; i < 40; i++) {
      const ageSeconds = Math.floor(Math.random() * 60);
      const ip = NORMAL_IPS[i % NORMAL_IPS.length];
      const ep = NORMAL_ENDPOINTS[i % NORMAL_ENDPOINTS.length];
      const method = ep.includes("login") ? "POST" : "GET";
      db.insertRequest({
        timestamp: new Date(now - ageSeconds * 1000).toISOString(),
        ip,
        method,
        path: ep,
        status_code: 200,
        response_time_ms: Math.round(8 + Math.random() * 25),
        user_agent: USER_AGENTS[i % USER_AGENTS.length],
      });
      requestsAdded++;
    }
    message = `Generated normal traffic burst (40 valid user requests).`;
  }

  // Trigger detections immediately
  const newAlerts = runAllDetections();
  return { type, message, requestsAdded, newAlerts };
}
