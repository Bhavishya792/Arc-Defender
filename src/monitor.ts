/**
 * ARC Defender — Request Monitoring Middleware
 *
 * Automatically captures HTTP request telemetry for monitored endpoints.
 */

import { Request, Response, NextFunction } from "express";
import { db } from "./database.js";

declare global {
  namespace Express {
    interface Request {
      arcStartTime?: number;
      arcLoginAttempt?: boolean;
      arcLoginSuccess?: boolean;
    }
  }
}

function getClientIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    const raw = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    return raw.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || req.ip || "127.0.0.1";
}

export function arcMonitorMiddleware(req: Request, res: Response, next: NextFunction) {
  req.arcStartTime = performance.now();
  req.arcLoginAttempt = false;
  req.arcLoginSuccess = false;

  // Track response size
  let responseSize = 0;
  const originalWrite = res.write;
  const originalEnd = res.end;

  res.write = function (chunk: any, ...args: any[]): boolean {
    if (chunk) {
      responseSize += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk);
    }
    return (originalWrite as any).apply(res, [chunk, ...args]);
  };

  res.end = function (chunk: any, ...args: any[]): any {
    if (chunk) {
      responseSize += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk);
    }
    return (originalEnd as any).apply(res, [chunk, ...args]);
  };

  res.on("finish", () => {
    const path = req.path || req.originalUrl || "/";
    // Skip monitoring the dashboard & arc API itself to avoid noise
    if (path.startsWith("/arc/")) {
      return;
    }

    const elapsedMs = req.arcStartTime ? performance.now() - req.arcStartTime : 0;
    const ip = getClientIp(req);
    const method = req.method;
    const statusCode = res.statusCode;
    const userAgent = (req.headers["user-agent"] as string) || "";
    const referer = (req.headers["referer"] as string) || "";
    const requestSize = parseInt((req.headers["content-length"] as string) || "0", 10) || 0;

    db.insertRequest({
      timestamp: new Date().toISOString(),
      ip,
      method,
      path,
      status_code: statusCode,
      response_time_ms: Math.round(elapsedMs * 100) / 100,
      user_agent: userAgent,
      referer,
      request_size: requestSize,
      response_size: responseSize,
      country: null,
      region: null,
      city: null,
      is_login_attempt: req.arcLoginAttempt ? 1 : 0,
      login_success: req.arcLoginSuccess ? 1 : 0,
    });
  });

  next();
}

export function markLogin(req: Request, success: boolean) {
  req.arcLoginAttempt = true;
  req.arcLoginSuccess = success;
}
