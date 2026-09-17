/**
 * ARC Defender Client SDK (TypeScript / Node.js)
 * 
 * Drop-in middleware for Express, Connect, and Next.js applications to stream
 * telemetry directly into your ARC Defender monitoring instance.
 */

export interface ArcConfig {
  /** Base URL of your ARC Defender instance (e.g. "http://localhost:3000" or custom domain) */
  endpoint?: string;
  /** Optional API Key or Secret */
  apiKey?: string;
  /** Paths to ignore (e.g. health checks, static files) */
  ignorePaths?: (string | RegExp)[];
  /** Batch timeout in milliseconds (default: 1000) */
  batchFlushIntervalMs?: number;
  /** Max batch buffer size (default: 50) */
  maxBatchSize?: number;
}

export interface TelemetryPayload {
  ip: string;
  method: string;
  path: string;
  status_code: number;
  response_time_ms: number;
  user_agent?: string;
  referer?: string;
  request_size?: number;
  response_size?: number;
  is_login_attempt?: boolean;
  login_success?: boolean;
  timestamp?: string;
}

export class ArcDefenderClient {
  private endpoint: string;
  private buffer: TelemetryPayload[] = [];
  private flushTimer: any = null;
  private maxBatchSize: number;
  private ignorePaths: (string | RegExp)[];

  constructor(config: ArcConfig = {}) {
    const base = config.endpoint || "http://localhost:3000";
    this.endpoint = base.replace(/\/+$/, "") + "/arc/api/v1/batch-ingest";
    this.maxBatchSize = config.maxBatchSize || 50;
    this.ignorePaths = config.ignorePaths || ["/health", "/favicon.ico", "/static/"];

    const interval = config.batchFlushIntervalMs || 1000;
    this.flushTimer = setInterval(() => this.flush(), interval);
    if (this.flushTimer.unref) this.flushTimer.unref();
  }

  public record(event: TelemetryPayload) {
    if (this.shouldIgnore(event.path)) return;
    this.buffer.push({
      ...event,
      timestamp: event.timestamp || new Date().toISOString()
    });

    if (this.buffer.length >= this.maxBatchSize) {
      this.flush();
    }
  }

  private shouldIgnore(path: string): boolean {
    return this.ignorePaths.some(p => typeof p === "string" ? path.startsWith(p) : p.test(path));
  }

  public async flush(): Promise<void> {
    if (this.buffer.length === 0) return;
    const batch = this.buffer.splice(0, this.buffer.length);

    try {
      await fetch(this.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(batch)
      });
    } catch (err: any) {
      // In production, buffer or log quietly to avoid blocking host app
      console.warn("[ARC Defender SDK] Telemetry transmission warning:", err.message);
    }
  }

  /**
   * Standard Express / Connect Middleware
   */
  public middleware() {
    return (req: any, res: any, next: any) => {
      const startTime = performance.now();
      let responseSize = 0;

      const originalWrite = res.write;
      const originalEnd = res.end;

      res.write = function (chunk: any, ...args: any[]): boolean {
        if (chunk) responseSize += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk);
        return originalWrite.apply(res, [chunk, ...args]);
      };

      res.end = function (chunk: any, ...args: any[]): any {
        if (chunk) responseSize += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk);
        return originalEnd.apply(res, [chunk, ...args]);
      };

      res.on("finish", () => {
        const elapsed = performance.now() - startTime;
        const forwarded = req.headers["x-forwarded-for"];
        const ip = (typeof forwarded === "string" ? forwarded.split(",")[0] : req.socket?.remoteAddress || req.ip || "127.0.0.1").trim();

        this.record({
          ip,
          method: req.method,
          path: req.originalUrl || req.url || "/",
          status_code: res.statusCode,
          response_time_ms: Math.round(elapsed * 100) / 100,
          user_agent: req.headers["user-agent"] || "",
          referer: req.headers["referer"] || "",
          request_size: parseInt(req.headers["content-length"] || "0", 10) || 0,
          response_size: responseSize,
          is_login_attempt: !!req.isLoginAttempt,
          login_success: !!req.loginSuccess
        });
      });

      next();
    };
  }
}
