/**
 * ARC Defender — REST API Endpoints Router
 */

import { Router, Request, Response } from "express";
import * as analytics from "./analytics.js";
import * as detection from "./detection.js";
import * as mlEngine from "./mlEngine.js";
import { db } from "./database.js";
import { simulateAttack } from "./simulator.js";

export const arcApi = Router();

function getHours(req: Request, defaultHours = 24): number {
  const q = req.query.hours;
  if (!q) return defaultHours;
  const parsed = parseInt(q as string, 10);
  return isNaN(parsed) ? defaultHours : parsed;
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

arcApi.get("/overview", (req: Request, res: Response) => {
  const hours = getHours(req);
  const stats = analytics.getOverviewStats(hours);
  res.json(stats);
});

arcApi.get("/overview/requests-over-time", (req: Request, res: Response) => {
  const hours = getHours(req);
  const data = analytics.getRequestsOverTime(hours);
  res.json(data);
});

// ---------------------------------------------------------------------------
// Traffic
// ---------------------------------------------------------------------------

arcApi.get("/traffic/endpoints", (req: Request, res: Response) => {
  const hours = getHours(req);
  const limit = parseInt((req.query.limit as string) || "10", 10);
  res.json(analytics.getRequestsByEndpoint(hours, limit));
});

arcApi.get("/traffic/methods", (req: Request, res: Response) => {
  const hours = getHours(req);
  res.json(analytics.getRequestsByMethod(hours));
});

arcApi.get("/traffic/status-codes", (req: Request, res: Response) => {
  const hours = getHours(req);
  res.json(analytics.getRequestsByStatus(hours));
});

arcApi.get("/traffic/latency", (req: Request, res: Response) => {
  const hours = getHours(req);
  res.json(analytics.getLatencyStats(hours));
});

arcApi.get("/traffic/errors", (req: Request, res: Response) => {
  const hours = getHours(req);
  res.json(analytics.getErrorStats(hours));
});

arcApi.get("/traffic/clients", (req: Request, res: Response) => {
  const hours = getHours(req);
  const limit = parseInt((req.query.limit as string) || "10", 10);
  res.json(analytics.getTopClients(hours, limit));
});

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

arcApi.get("/requests", (req: Request, res: Response) => {
  const hours = getHours(req);
  const limit = parseInt((req.query.limit as string) || "50", 10);
  const offset = parseInt((req.query.offset as string) || "0", 10);
  const search = req.query.search as string;
  const method = req.query.method as string;
  const status_group = req.query.status_group as string;
  const status_code = req.query.status_code ? parseInt(req.query.status_code as string, 10) : undefined;
  const ip = req.query.ip as string;
  const min_latency = req.query.min_latency ? parseFloat(req.query.min_latency as string) : undefined;
  const errors_only = req.query.errors_only === "true" || req.query.errors_only === "1";

  const result = analytics.getRecentRequests({
    hours,
    limit,
    offset,
    search,
    method,
    status_group,
    status_code,
    ip,
    min_latency,
    errors_only,
  });

  res.json(result);
});

arcApi.get("/requests/:id", (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  const detail = analytics.getRequestDetail(id);
  if (!detail) {
    res.status(404).json({ error: "Request not found" });
    return;
  }
  res.json(detail);
});

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

arcApi.get("/clients/:ip(*)", (req: Request, res: Response) => {
  const ip = req.params.ip;
  const detail = analytics.getClientDetail(ip);
  if (!detail) {
    res.status(404).json({ error: "Client not found" });
    return;
  }
  res.json(detail);
});

// ---------------------------------------------------------------------------
// Security & Threat Alerting
// ---------------------------------------------------------------------------

arcApi.get(["/security/threat-status", "/threat-status"], (req: Request, res: Response) => {
  const hours = getHours(req);
  res.json(detection.getThreatStatus(hours));
});

arcApi.get("/security/alerts", (req: Request, res: Response) => {
  const hours = getHours(req);
  const limit = parseInt((req.query.limit as string) || "50", 10);
  const severity = req.query.severity as string;
  const status = req.query.status as "active" | "acknowledged" | "all" | undefined;
  res.json(detection.getAlerts(hours, limit, severity, status));
});

arcApi.post("/security/alerts/:id/acknowledge", (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  const success = db.acknowledgeAlert(id);
  if (!success) {
    res.status(404).json({ error: "Alert not found" });
    return;
  }
  res.json({ success: true, id });
});

arcApi.post("/security/alerts/acknowledge-all", (req: Request, res: Response) => {
  const acknowledged = db.acknowledgeAllAlerts();
  res.json({ success: true, acknowledged });
});

arcApi.post("/security/alerts/clear", (req: Request, res: Response) => {
  db.clearAlerts();
  res.json({ success: true, message: "Alerts cleared" });
});

arcApi.get("/security/suspicious-clients", (req: Request, res: Response) => {
  const hours = getHours(req);
  res.json(detection.getSuspiciousClients(hours));
});

arcApi.get("/security/risk/:ip(*)", (req: Request, res: Response) => {
  const ip = req.params.ip;
  res.json(detection.calculateRiskScore(ip));
});

arcApi.post("/security/detect", (req: Request, res: Response) => {
  const alerts = detection.runAllDetections();
  res.json({ alerts_generated: alerts.length, alerts });
});

// ---------------------------------------------------------------------------
// Threat Simulation
// ---------------------------------------------------------------------------

arcApi.post("/simulator/simulate", (req: Request, res: Response) => {
  const type = (req.body && req.body.type) || (req.query.type as string) || "brute_force";
  const result = simulateAttack(type);
  res.json(result);
});

// ---------------------------------------------------------------------------
// ML
// ---------------------------------------------------------------------------

arcApi.get("/ml/results", (req: Request, res: Response) => {
  const hours = getHours(req);
  res.json(mlEngine.getMlResults(hours));
});

arcApi.get("/ml/status", (req: Request, res: Response) => {
  res.json(mlEngine.getMlStatus());
});

arcApi.post("/ml/run", (req: Request, res: Response) => {
  const hours = getHours(req, 24);
  const result = mlEngine.trainAndScore(hours);
  if (!result) {
    res.json({ trained: false, reason: "Insufficient data for ML training" });
    return;
  }
  res.json(result);
});

// ---------------------------------------------------------------------------
// External Ingestion API (Developer Integration for Custom APIs)
// ---------------------------------------------------------------------------

arcApi.post("/v1/ingest", (req: Request, res: Response) => {
  const body = req.body;
  if (!body || typeof body !== "object") {
    res.status(400).json({ error: "Invalid payload. JSON object expected." });
    return;
  }

  const record = db.insertRequest({
    timestamp: body.timestamp || new Date().toISOString(),
    ip: body.ip || (req.headers["x-forwarded-for"] as string) || req.socket?.remoteAddress || "127.0.0.1",
    method: (body.method || "GET").toUpperCase(),
    path: body.path || "/",
    status_code: typeof body.status_code === "number" ? body.status_code : 200,
    response_time_ms: typeof body.response_time_ms === "number" ? body.response_time_ms : (body.latency_ms || 10),
    user_agent: body.user_agent || (req.headers["user-agent"] as string) || "",
    referer: body.referer || "",
    request_size: body.request_size || 0,
    response_size: body.response_size || 0,
    country: body.country || null,
    region: body.region || null,
    city: body.city || null,
    is_login_attempt: body.is_login_attempt ? 1 : 0,
    login_success: body.login_success ? 1 : 0,
  });

  res.status(201).json({
    success: true,
    message: "Telemetry event recorded successfully",
    event_id: record.id,
    timestamp: record.timestamp,
  });
});

arcApi.post("/v1/batch-ingest", (req: Request, res: Response) => {
  const events = req.body;
  if (!Array.isArray(events)) {
    res.status(400).json({ error: "Invalid payload. Array of event objects expected." });
    return;
  }

  const insertedIds: number[] = [];
  for (const item of events) {
    if (item && typeof item === "object") {
      const record = db.insertRequest({
        timestamp: item.timestamp || new Date().toISOString(),
        ip: item.ip || "127.0.0.1",
        method: (item.method || "GET").toUpperCase(),
        path: item.path || "/",
        status_code: typeof item.status_code === "number" ? item.status_code : 200,
        response_time_ms: typeof item.response_time_ms === "number" ? item.response_time_ms : 10,
        user_agent: item.user_agent || "",
        referer: item.referer || "",
        request_size: item.request_size || 0,
        response_size: item.response_size || 0,
        country: item.country || null,
        region: item.region || null,
        city: item.city || null,
        is_login_attempt: item.is_login_attempt ? 1 : 0,
        login_success: item.login_success ? 1 : 0,
      });
      insertedIds.push(record.id);
    }
  }

  res.status(201).json({
    success: true,
    ingested_count: insertedIds.length,
    message: `Batch ingestion complete. ${insertedIds.length} telemetry records recorded.`,
  });
});

arcApi.get("/v1/schema", (req: Request, res: Response) => {
  res.json({
    title: "ARC Defender Ingestion Schema",
    endpoint: "/arc/api/v1/ingest",
    batch_endpoint: "/arc/api/v1/batch-ingest",
    supported_methods: ["POST"],
    fields: {
      ip: { type: "string", required: true, description: "Client IP address (IPv4 or IPv6)" },
      method: { type: "string", required: false, default: "GET", description: "HTTP method" },
      path: { type: "string", required: true, description: "HTTP request URI path" },
      status_code: { type: "number", required: false, default: 200, description: "HTTP response status code" },
      response_time_ms: { type: "number", required: false, default: 10, description: "Total roundtrip latency in ms" },
      user_agent: { type: "string", required: false, description: "Client User-Agent header" },
      referer: { type: "string", required: false, description: "HTTP Referer header" },
      request_size: { type: "number", required: false, default: 0, description: "Request payload size in bytes" },
      response_size: { type: "number", required: false, default: 0, description: "Response payload size in bytes" },
      is_login_attempt: { type: "boolean", required: false, default: false, description: "Whether this request was an authentication endpoint" },
      login_success: { type: "boolean", required: false, default: false, description: "Whether the authentication succeeded" }
    }
  });
});
